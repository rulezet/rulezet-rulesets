import "pe"
rule _PECompact_099_
{
	meta:
		description = "PECompact 0.99"
	strings:
		$0 = {EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 00 87 DD 8B 85 B4 85 40 00 01 85 23 85 40 00 66 C7 85 20 85 40 00 90 90 BB C0 09 00 00 03 9D B8 85 40 00 03 9D B4 85 40 00 53 53 53 58 2D 8A}
	condition:
		$0 at pe.entry_point
}