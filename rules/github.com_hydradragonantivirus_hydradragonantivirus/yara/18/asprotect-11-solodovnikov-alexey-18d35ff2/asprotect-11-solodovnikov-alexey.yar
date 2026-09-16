import "pe"
rule _ASProtect_11__Solodovnikov_Alexey_
{
	meta:
		description = "ASProtect 1.1 -> Solodovnikov Alexey"
	strings:
		$0 = {60 E9 ?? 04 00 00 E9 ?? ?? ?? ?? ?? ?? ?? EE}
	condition:
		$0 at pe.entry_point
}