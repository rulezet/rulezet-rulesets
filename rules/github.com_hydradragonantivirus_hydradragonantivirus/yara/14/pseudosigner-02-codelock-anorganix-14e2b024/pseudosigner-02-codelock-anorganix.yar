import "pe"
rule _PseudoSigner_02_CodeLock__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Code-Lock] --> Anorganix"
	strings:
		$0 = {43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B}
	condition:
		$0 at pe.entry_point
}