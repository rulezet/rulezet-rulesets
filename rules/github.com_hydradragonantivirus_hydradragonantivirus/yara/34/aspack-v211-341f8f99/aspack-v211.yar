import "pe"
rule _ASPack_v211_
{
	meta:
		description = "ASPack v2.11"
	strings:
		$0 = {60 E8 02 ?? ?? ?? EB 09 5D 55 81 ED 39 39 44 ?? C3 E9 3D}
	condition:
		$0 at pe.entry_point
}