import "pe"
rule _ASPack_107b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.07b -> Solodovnikov Alexey"
	strings:
		$0 = {90 75 ?? E9}
	condition:
		$0 at pe.entry_point
}