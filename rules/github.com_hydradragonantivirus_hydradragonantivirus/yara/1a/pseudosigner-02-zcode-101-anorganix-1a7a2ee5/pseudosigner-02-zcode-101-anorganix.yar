import "pe"
rule _PseudoSigner_02_ZCode_101__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [ZCode 1.01] --> Anorganix"
	strings:
		$0 = {E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00}
	condition:
		$0 at pe.entry_point
}