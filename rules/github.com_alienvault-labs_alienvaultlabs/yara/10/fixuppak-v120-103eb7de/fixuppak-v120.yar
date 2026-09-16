rule _FixupPak_v120_
{
	meta:
		description = "FixupPak v1.20"
	strings:
		$0 = {83 EC 0C 53 56 57 E8 24}
	condition:
		$0 at entrypoint
}