import "pe"
rule _PseudoSigner_02_Microsoft_Visual_Basic_50__60_
{
	meta:
		description = "PseudoSigner 0.2 [Microsoft Visual Basic 5.0 - 6.0"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00}
	condition:
		$0 at pe.entry_point
}