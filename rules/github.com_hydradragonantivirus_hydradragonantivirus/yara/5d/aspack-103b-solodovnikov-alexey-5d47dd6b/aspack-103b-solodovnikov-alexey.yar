import "pe"
rule _ASPack_103b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.03b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED AE 98 43 00 B8 A8 98 43 00 03 C5 2B 85 18 9D 43 00 89 85 24 9D 43 00 80 BD 0E 9D 43}
	condition:
		$0 at pe.entry_point
}