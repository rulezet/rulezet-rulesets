import "pe"
rule _PseudoSigner_02_PE_Intro_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PE Intro 1.0] --> Anorganix"
	strings:
		$0 = {8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A}
	condition:
		$0 at pe.entry_point
}