rule _PECompact_v14xp_
{
	meta:
		description = "PECompact v1.4x+"
	strings:
		$0 = {33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC}
	condition:
		$0 at entrypoint
}