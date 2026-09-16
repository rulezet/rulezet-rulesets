import "pe"
rule _PseudoSigner_01_Morphine_12__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Morphine 1.2] --> Anorganix"
	strings:
		$0 = {90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}