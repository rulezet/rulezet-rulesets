import "pe"
rule _ASPack_v10802_
{
	meta:
		description = "ASPack v1.08.02"
	strings:
		$0 = {60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 ?? BB 10 6A 44 ?? 03 DD 2B 9D}
	condition:
		$0 at pe.entry_point
}