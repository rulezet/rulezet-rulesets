rule _PECompact_v0971__v0976_
{
	meta:
		description = "PECompact v0.971 - v0.976"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 87 DD 8B 85 2A}
	condition:
		$0 at entrypoint
}