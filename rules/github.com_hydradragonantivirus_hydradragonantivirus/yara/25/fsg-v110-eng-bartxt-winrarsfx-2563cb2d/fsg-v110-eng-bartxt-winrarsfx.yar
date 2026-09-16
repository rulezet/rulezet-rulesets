import "pe"
rule _FSG_v110_Eng__bartxt__WinRARSFX_
{
	meta:
		description = "FSG v1.10 (Eng) -> bart/xt -> WinRAR-SFX"
	strings:
		$0 = {80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0}
		$1 = {EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}