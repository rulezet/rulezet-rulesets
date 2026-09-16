import "pe"
rule _ASPack_v108x__Alexey_Solodovnikov_
{
	meta:
		description = "ASPack v1.08.x -> Alexey Solodovnikov"
	strings:
		$0 = {60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A}
	condition:
		$0 at pe.entry_point
}