import "pe"
rule _ASProtect_v11_MTEc_
{
	meta:
		description = "ASProtect v1.1 MTEc"
	strings:
		$0 = {60 E9}
	condition:
		$0 at pe.entry_point
}