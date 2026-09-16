import "pe"
rule _Microsoft_Visual_Cue_80_
{
	meta:
		description = "Microsoft Visual Cue 8.0"
	strings:
		$0 = {6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B}
	condition:
		$0 at pe.entry_point
}