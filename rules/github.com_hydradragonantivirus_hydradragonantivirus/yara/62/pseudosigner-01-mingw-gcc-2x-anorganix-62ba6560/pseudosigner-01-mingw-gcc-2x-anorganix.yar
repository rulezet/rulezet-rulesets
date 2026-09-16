import "pe"
rule _PseudoSigner_01_MinGW_GCC_2x__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [MinGW GCC 2.x] --> Anorganix"
	strings:
		$0 = {55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9}
	condition:
		$0 at pe.entry_point
}