rule _PECompact_v09782_
{
	meta:
		description = "PECompact v0.978.2"
	strings:
		$0 = {EB 06 68 C3 9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 87 DD 8B 85 5C}
	condition:
		$0 at entrypoint
}