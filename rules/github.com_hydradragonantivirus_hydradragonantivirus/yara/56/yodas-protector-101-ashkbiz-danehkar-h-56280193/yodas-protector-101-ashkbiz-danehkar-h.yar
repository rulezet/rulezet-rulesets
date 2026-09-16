import "pe"
rule _yodas_Protector_101__Ashkbiz_Danehkar_h_
{
	meta:
		description = "yoda's Protector 1.01 -> Ashkbiz Danehkar (h)"
	strings:
		$0 = {55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}