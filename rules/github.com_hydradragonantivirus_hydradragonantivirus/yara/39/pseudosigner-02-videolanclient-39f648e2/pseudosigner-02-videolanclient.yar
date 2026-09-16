import "pe"
rule _PseudoSigner_02_VideoLanClient_
{
	meta:
		description = "PseudoSigner 0.2 [Video-Lan-Client"
	strings:
		$0 = {55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01}
	condition:
		$0 at pe.entry_point
}