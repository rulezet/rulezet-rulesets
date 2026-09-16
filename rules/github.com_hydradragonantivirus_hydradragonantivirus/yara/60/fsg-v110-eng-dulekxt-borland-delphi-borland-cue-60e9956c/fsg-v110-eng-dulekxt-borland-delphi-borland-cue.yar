import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Delphi__Borland_Cue_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland Cue)"
	strings:
		$0 = {2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7}
	condition:
		$0 at pe.entry_point
}