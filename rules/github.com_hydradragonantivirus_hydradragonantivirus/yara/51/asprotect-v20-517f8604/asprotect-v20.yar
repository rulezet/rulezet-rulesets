rule _ASProtect_v20_
{
	meta:
		description = "ASProtect v2.0"
	strings:
		$0 = {68 01 ?? 40 00 E8 01 00 00 00 C3 C3}
	condition:
		$0
}