import "pe"
rule _PECompact_140b5__140b6_
{
	meta:
		description = "PECompact 1.40b5 - 1.40b6"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 00 87 DD 8B 85 A6 A0 40 00 01 85 03 A0 40 00 66 C7 85 00 A0 40 00 90 90 01 85 9E A0 40 00 BB 8A 11 00 00 03 9D AA A0 40 00 03 9D A6 A0 40 00}
	condition:
		$0 at pe.entry_point
}