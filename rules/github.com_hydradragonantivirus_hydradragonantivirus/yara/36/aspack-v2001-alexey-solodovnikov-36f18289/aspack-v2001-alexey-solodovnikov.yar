import "pe"
rule _ASPack_v2001__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v2.001 -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 72 05 00 00 EB 4C}
	condition:
		$0 at pe.entry_point
}