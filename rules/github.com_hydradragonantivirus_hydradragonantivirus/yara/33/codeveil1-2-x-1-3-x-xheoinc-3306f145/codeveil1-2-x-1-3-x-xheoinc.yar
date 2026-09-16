import "pe"
rule CodeVeil1_2_x_1_3_x__XheoInc_
{
	meta:
		author = "PEiD"
		description = "CodeVeil 1.2.x/1.3.x -> Xheo Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B FF 60 E8 01 00 00 00 B8 5E E8 01 00 00 00 B8 58 2D 31 01 00 00 8B 00 2B F0 81 E6 00 00 FF FF 03 76 3C 33 C9 66 8B 4E 14 8D 74 31 18 8B 5E 0C 03 DE 81 E3 00 F0 FF FF 8B 56 08 E8 05 00 00 00 E9 93 00 00 00 55 8B EC 83 C4 F0 B9 E9 00 00 00 8B F3 03 DA E8 01 00 00 00 B8 58 2D 77 01 00 00 8B 00 03 C6 89 45 F4 E8 01 00 00 00 B8 5A 81 EA 86 01 00 00 8B 12 03 D0 89 55 F0 E8 01 00 00 00 B8 5A 81 EA A6 01 00 00 8B 12 E8 01 00 00 00 E9 5F 81 C7 A3 00 00 00 03 D7 }
	condition:
		$a0 at pe.entry_point
}