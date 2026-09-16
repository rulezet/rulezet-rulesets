import "pe"
rule _Shrink_20_2_
{
	meta:
		description = "Shrink 2.0 (2)"
	strings:
		$0 = {50 9C FC BE 27 01 8B FE 8C C8 05 00 10 8E C0 06 57 B9 41 00 F3 A4 8B 0E 23 01 BE 68 01 F3 A4 CB 00 00 00 00 BE 68 01 8B 0E 23 01 8A 26 25 01 1E 06 1F 07 BF 00 01 57 AC 3A C4 74 13 8A D8 AA E2 F6 5B 9D 58 06 53 8B D9 8B F1 8B F9 06 1F CB AC}
	condition:
		$0 at pe.entry_point
}