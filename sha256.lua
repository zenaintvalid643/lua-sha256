--[[

GitHub: https://github.com/yourusername/lua-sha256
Pure Lua SHA-256 Implementation
Compatible with Lua 5.1, 5.2, 5.3, LuaJIT, and Roblox LuaU

]]



local bit = bit32
local string = string

local sha256 = {}

local function rrotate(x, n)
	return bit.rshift(x, n) + bit.lshift(x, 32 - n)
end




function sha256.hash(str)
	local k = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}

	local h = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	}

	local function preproc(str)
		local msg_len = #str
		str = str .. "\x80"
		while (#str % 64) ~= 56 do
			str = str .. "\0"
		end
		local len = msg_len * 8
		for i = 8, 1, -1 do
			str = str .. string.char(bit.band(bit.rshift(len, (i - 1) * 8), 0xFF))
		end
		return str
	end

	local function digestblock(block, h)
		local w = {}
		for i = 0, 15 do
			w[i] = bit.bor(
				bit.lshift(block:byte(i*4+1), 24),
				bit.lshift(block:byte(i*4+2), 16),
				bit.lshift(block:byte(i*4+3), 8),
				block:byte(i*4+4)
			)
		end
		for i = 16, 63 do
			local s0 = bit.bxor(rrotate(w[i-15], 7), rrotate(w[i-15], 18), bit.rshift(w[i-15], 3))
			local s1 = bit.bxor(rrotate(w[i-2], 17), rrotate(w[i-2], 19), bit.rshift(w[i-2], 10))
			w[i] = (w[i-16] + s0 + w[i-7] + s1) % 0x100000000
		end
		
		

		local a, b, c, d, e, f, g, hh = h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]

		for i = 0, 63 do
			local S1 = bit.bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
			local ch = bit.bxor(bit.band(e, f), bit.band(bit.bnot(e), hh))
			local temp1 = (hh + S1 + ch + k[i+1] + w[i]) % 0x100000000
			local S0 = bit.bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
			local maj = bit.bxor(bit.band(a, b), bit.band(a, c), bit.band(b, c))
			local temp2 = (S0 + maj) % 0x100000000

			hh = g
			g = f
			f = e
			e = (d + temp1) % 0x100000000
			d = c
			c = b
			b = a
			a = (temp1 + temp2) % 0x100000000
		end

		h[1] = (h[1] + a) % 0x100000000
		h[2] = (h[2] + b) % 0x100000000
		h[3] = (h[3] + c) % 0x100000000
		h[4] = (h[4] + d) % 0x100000000
		h[5] = (h[5] + e) % 0x100000000
		h[6] = (h[6] + f) % 0x100000000
		h[7] = (h[7] + g) % 0x100000000
		h[8] = (h[8] + hh) % 0x100000000
	end

	str = preproc(str)
	for i = 1, #str, 64 do
		digestblock(str:sub(i, i + 63), h)
	end

	local digest = ""
	for i = 1, 8 do
		digest = digest .. string.format("%08x", h[i])
	end

	return digest
end

return sha256
