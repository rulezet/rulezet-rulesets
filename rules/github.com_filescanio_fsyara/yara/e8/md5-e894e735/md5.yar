rule MD5 : hardened
{
	meta:
		description = "Uses constants related to MD5"
		author = "Ivan Kwiatkowski (@JusticeRage)"

	strings:
		$mac_t0 = { 97 ef 45 ac 29 0f 43 cd 45 7e 1b 55 1c 80 11 34 }
		$mac_t1 = { b1 77 ce 96 2e 72 8e 7c 5f 5a ab 0a 36 43 be 18 }
		$mac_t2 = { 9d 21 b4 21 bc 87 b9 4d a2 9d 27 bd c7 5b d7 c3 }
		$md5_c0 = { 78 A4 6A D7 }
		$md5_c1 = { 56 B7 C7 E8 }
		$md5_c2 = { DB 70 20 24 }
		$md5_c3 = { EE CE BD C1 }
		$md5_c4 = { AF 0F 7C F5 }
		$md5_c5 = { 2A C6 87 47 }
		$md5_c6 = { 13 46 30 A8 }
		$md5_c7 = { 01 95 46 FD }
		$md5_c8 = { D8 98 80 69 }
		$md5_c9 = { AF F7 44 8B }
		$md5_c10 = { B1 5B FF FF }
		$md5_c11 = { BE D7 5C 89 }
		$md5_c12 = { 22 11 90 6B }
		$md5_c13 = { 93 71 98 FD }
		$md5_c14 = { 8E 43 79 A6 }
		$md5_c15 = { 21 08 B4 49 }
		$md5_c16 = { 62 25 1E F6 }
		$md5_c17 = { 40 B3 40 C0 }
		$md5_c18 = { 51 5A 5E 26 }
		$md5_c19 = { AA C7 B6 E9 }
		$md5_c20 = { 5D 10 2F D6 }
		$md5_c21 = { 53 14 44 02 }
		$md5_c22 = { 81 E6 A1 D8 }
		$md5_c23 = { C8 FB D3 E7 }
		$md5_c24 = { E6 CD E1 21 }
		$md5_c25 = { D6 07 37 C3 }
		$md5_c26 = { 87 0D D5 F4 }
		$md5_c27 = { ED 14 5A 45 }
		$md5_c28 = { 05 E9 E3 A9 }
		$md5_c29 = { F8 A3 EF FC }
		$md5_c30 = { D9 02 6F 67 }
		$md5_c31 = { 8A 4C 2A 8D }
		$md5_c32 = { 42 39 FA FF }
		$md5_c33 = { 81 F6 71 87 }
		$md5_c34 = { 22 61 9D 6D }
		$md5_c35 = { 0C 38 E5 FD }
		$md5_c36 = { 44 EA BE A4 }
		$md5_c37 = { A9 CF DE 4B }
		$md5_c38 = { 60 4B BB F6 }
		$md5_c39 = { 70 BC BF BE }
		$md5_c40 = { C6 7E 9B 28 }
		$md5_c41 = { FA 27 A1 EA }
		$md5_c42 = { 85 30 EF D4 }
		$md5_c43 = { 05 1D 88 04 }
		$md5_c44 = { 39 D0 D4 D9 }
		$md5_c45 = { E5 99 DB E6 }
		$md5_c46 = { F8 7C A2 1F }
		$md5_c47 = { 65 56 AC C4 }
		$md5_c48 = { 44 22 29 F4 }
		$md5_c49 = { 97 FF 2A 43 }
		$md5_c50 = { A7 23 94 AB }
		$md5_c51 = { 39 A0 93 FC }
		$md5_c52 = { C3 59 5B 65 }
		$md5_c53 = { 92 CC 0C 8F }
		$md5_c54 = { 7D F4 EF FF }
		$md5_c55 = { D1 5D 84 85 }
		$md5_c56 = { 4F 7E A8 6F }
		$md5_c57 = { E0 E6 2C FE }
		$md5_c58 = { 14 43 01 A3 }
		$md5_c59 = { A1 11 08 4E }
		$md5_c60 = { 82 7E 53 F7 }
		$md5_c61 = { 35 F2 3A BD }
		$md5_c62 = { BB D2 D7 2A }
		$md5_c63 = { 91 D3 86 EB }

	condition:
		any of ( $mac_* ) or 20 of ( $md5_c* )
}