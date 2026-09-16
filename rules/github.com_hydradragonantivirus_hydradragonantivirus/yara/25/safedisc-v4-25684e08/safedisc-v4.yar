rule _SafeDisc_v4_
{
	meta:
		description = "SafeDisc v4"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F}
	condition:
		$0
}