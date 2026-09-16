import "pe"
rule _nPack_v113002006_Beta_
{
	meta:
		description = "nPack v1.1.300.2006 Beta"
	strings:
		$0 = {83 3D 4C ?? ?? 00 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00}
	condition:
		$0 at pe.entry_point
}