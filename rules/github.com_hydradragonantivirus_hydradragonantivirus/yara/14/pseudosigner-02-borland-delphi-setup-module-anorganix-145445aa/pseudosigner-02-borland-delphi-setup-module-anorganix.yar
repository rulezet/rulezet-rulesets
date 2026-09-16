import "pe"
rule _PseudoSigner_02_Borland_Delphi_Setup_Module__Anorganix_
{
	meta:
		description = "PseudoSigner 0.2 [Borland Delphi Setup Module] --> Anorganix"
	strings:
		$0 = {55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}