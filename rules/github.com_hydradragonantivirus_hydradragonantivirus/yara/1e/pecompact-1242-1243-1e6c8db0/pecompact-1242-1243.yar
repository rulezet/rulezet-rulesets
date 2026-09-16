import "pe"
rule _PECompact_1242__1243_
{
	meta:
		description = "PECompact 1.24.2 - 1.24.3"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 00 87 DD 8B 85 A6 70 40 00 01 85 03 70 40 00 66 C7 85 00 70 40 00 90 90 01 85 9E 70 40 00 BB D2 09 00 00 03 9D AA 70 40 00 03 9D A6 70 40 00}
	condition:
		$0 at pe.entry_point
}