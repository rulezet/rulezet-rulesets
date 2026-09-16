import "pe"
rule _PseudoSigner_01_VideoLanClient__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Video-Lan-Client] --> Anorganix"
	strings:
		$0 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9}
	condition:
		$0 at pe.entry_point
}