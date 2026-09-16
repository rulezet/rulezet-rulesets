rule _WWPack32_v100_v111_v112_v120_
{
	meta:
		description = "WWPack32 v1.00, v1.11, v1.12, v1.20"
	strings:
		$0 = {53 55 8B E8 33 DB EB}
	condition:
		$0 at entrypoint
}