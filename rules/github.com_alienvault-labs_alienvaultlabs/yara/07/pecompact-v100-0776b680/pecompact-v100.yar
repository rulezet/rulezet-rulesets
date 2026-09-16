rule _PECompact_v100_
{
	meta:
		description = "PECompact v1.00"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 87 DD 8B 85 AD}
	condition:
		$0 at entrypoint
}