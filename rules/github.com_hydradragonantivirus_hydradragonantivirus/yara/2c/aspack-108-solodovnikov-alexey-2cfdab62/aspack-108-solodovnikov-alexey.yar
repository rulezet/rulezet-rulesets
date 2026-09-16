import "pe"
rule _ASPack_108__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.08 -> Solodovnikov Alexey"
	strings:
		$0 = {90 75 01 FF E9}
	condition:
		$0 at pe.entry_point
}