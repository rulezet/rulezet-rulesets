import "pe"
rule _ASPack_105b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.05b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED CE 3A 44 00 B8 C8 3A 44 00 03 C5 2B 85 B5 3E 44 00 89 85 C1 3E 44 00 80 BD AC 3E 44}
	condition:
		$0 at pe.entry_point
}