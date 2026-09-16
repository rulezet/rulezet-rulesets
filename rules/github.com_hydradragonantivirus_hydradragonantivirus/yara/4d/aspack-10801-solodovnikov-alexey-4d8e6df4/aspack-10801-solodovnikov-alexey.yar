import "pe"
rule _ASPack_10801__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.08.01 -> Solodovnikov Alexey"
	strings:
		$0 = {90 75 ?? 90 E9}
	condition:
		$0 at pe.entry_point
}