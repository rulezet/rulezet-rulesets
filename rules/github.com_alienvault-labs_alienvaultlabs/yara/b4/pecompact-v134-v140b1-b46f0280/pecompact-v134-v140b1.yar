rule _PECompact_v134__v140b1_
{
	meta:
		description = "PECompact v1.34 - v1.40b1"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 87 DD 8B 85 A6 A0 40 01 85 03 A0 40 66 C7 85 A0 40 90 90 01 85 9E A0 40}
	condition:
		$0 at entrypoint
}