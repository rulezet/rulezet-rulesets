import "pe"
rule _ASProtect_v11_MTE_
{
	meta:
		description = "ASProtect v1.1 MTE"
	strings:
		$0 = {90 60 E9}
	condition:
		$0 at pe.entry_point
}