import "pe"
rule _ASPack_211__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 2.11 -> Solodovnikov Alexey"
	strings:
		$0 = {60 E9 3D 04 00 00}
	condition:
		$0 at pe.entry_point
}