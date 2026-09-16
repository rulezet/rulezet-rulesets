import "pe"
rule _PseudoSigner_01_Neolite_20__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Neolite 2.0] --> Anorganix"
	strings:
		$0 = {E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}