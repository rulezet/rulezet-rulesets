rule _LTC_v13_
{
	meta:
		description = "LTC v1.3"
	strings:
		$0 = {2C E8 5D 8B C5 81 ED F6 73 2B 85 83 E8 06 89}
	condition:
		$0 at entrypoint
}