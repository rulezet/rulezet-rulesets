import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cue_50p_MFC_
{
	meta:
		description = "PseudoSigner 0.1 [Microsoft Visual Cue 5.0+ (MFC)"
	strings:
		$0 = {55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9}
	condition:
		$0 at pe.entry_point
}