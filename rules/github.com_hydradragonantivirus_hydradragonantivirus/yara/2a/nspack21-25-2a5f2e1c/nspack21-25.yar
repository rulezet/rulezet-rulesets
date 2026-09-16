import "pe"
rule nspack21_25
{
	meta:
		author = "PEiD"
		description = "nSPack 2.1 - 2.5 -> North Star/Liu Xing Ping"
		group = "555"
		function = "0"
	strings:
		$a0 = { 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 5D C2 08 00 6A 00 FF 95 ?? ?? ?? ?? C3 8B 00 11 3B 51 04 75 0A C7 41 38 10 01 60 02 0C FF C3 8A 0E 02 42 89 11 C0 8B 44 24 04 83 38 61 10 67 08 0C 06 56 20 3C 03 D0 83 49 08 FF 6A 05 D6 58 1E 5E E8 C9 73 02 8B C8 0C 0F B6 00 C0 C1 E2 08 0B C2 4E 89 7C 41 1E 75 EA 5E 1C 04 00 53 56 8B 71 08 33 0F DB 85 D2 57 00 }
	condition:
		$a0 at pe.entry_point
}