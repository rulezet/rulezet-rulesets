import "pe"
rule _ASPack_104b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.04b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED ?? ?? ?? 00 B8 ?? ?? ?? 00 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D ?? 00 80 BD 08 9D ?? 00 00}
	condition:
		$0 at pe.entry_point
}