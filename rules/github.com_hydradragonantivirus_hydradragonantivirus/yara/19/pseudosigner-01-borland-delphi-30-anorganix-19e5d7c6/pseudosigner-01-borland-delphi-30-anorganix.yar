import "pe"
rule _PseudoSigner_01_Borland_Delphi_30__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Borland Delphi 3.0] --> Anorganix"
	strings:
		$0 = {55 8B EC 83 C4 90 90 90 90 68 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}