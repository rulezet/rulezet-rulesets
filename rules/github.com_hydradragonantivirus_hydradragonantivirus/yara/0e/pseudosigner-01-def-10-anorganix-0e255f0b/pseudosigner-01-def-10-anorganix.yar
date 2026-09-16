import "pe"
rule _PseudoSigner_01_DEF_10__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [DEF 1.0] --> Anorganix"
	strings:
		$0 = {BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9}
	condition:
		$0 at pe.entry_point
}