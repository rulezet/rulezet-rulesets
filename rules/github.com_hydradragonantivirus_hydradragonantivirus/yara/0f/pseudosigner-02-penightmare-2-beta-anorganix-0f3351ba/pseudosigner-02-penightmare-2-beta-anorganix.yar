import "pe"
rule _PseudoSigner_02_PENightMare_2_Beta__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [PENightMare 2 Beta] --> Anorganix"
	strings:
		$0 = {60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A}
	condition:
		$0 at pe.entry_point
}