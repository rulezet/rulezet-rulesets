import "pe"
rule _yodas_Protector_102__103__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.02 - 1.03 -> Ashkbiz Danehkar"
	strings:
		$0 = {E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00}
	condition:
		$0 at pe.entry_point
}