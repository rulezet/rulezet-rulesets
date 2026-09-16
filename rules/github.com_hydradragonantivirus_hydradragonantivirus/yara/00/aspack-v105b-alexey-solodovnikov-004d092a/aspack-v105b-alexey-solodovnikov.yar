import "pe"
rule _ASPack_v105b__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.05b -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44}
	condition:
		$0 at pe.entry_point
}