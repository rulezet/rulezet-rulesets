import "pe"
rule _PseudoSigner_01_PE_Intro_10_
{
	meta:
		description = "PseudoSigner 0.1 [PE Intro 1.0"
	strings:
		$0 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9}
		$1 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}