import "pe"
rule _ASPack_v1061b__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.061b -> Alexey Solodovnikov"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43}
	condition:
		$0 at pe.entry_point
}