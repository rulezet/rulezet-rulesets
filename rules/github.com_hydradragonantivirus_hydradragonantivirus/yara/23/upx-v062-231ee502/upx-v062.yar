import "pe"
rule _UPX_v062_
{
	meta:
		description = "UPX v0.62"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 58 83 E8 3D 50 8D B8 FF 57 66 81 87 8D B0 EC 01 83 CD FF 31 DB EB 07 90 8A 06 46 88 07 47 01 DB 75}
	condition:
		$0 at pe.entry_point
}