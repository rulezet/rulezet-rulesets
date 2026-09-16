import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cue_60_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Cue 6.0)"
	strings:
		$0 = {EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}