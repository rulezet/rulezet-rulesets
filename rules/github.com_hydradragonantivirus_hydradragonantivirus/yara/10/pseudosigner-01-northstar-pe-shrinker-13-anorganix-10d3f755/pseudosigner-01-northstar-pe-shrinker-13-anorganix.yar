import "pe"
rule _PseudoSigner_01_NorthStar_PE_Shrinker_13__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [NorthStar PE Shrinker 1.3] --> Anorganix"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9}
	condition:
		$0 at pe.entry_point
}