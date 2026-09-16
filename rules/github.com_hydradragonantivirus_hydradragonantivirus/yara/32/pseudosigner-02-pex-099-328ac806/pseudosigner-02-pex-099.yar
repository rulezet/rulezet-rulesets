import "pe"
rule _PseudoSigner_02_PEX_099_
{
	meta:
		description = "PseudoSigner 0.2 [PEX 0.99"
	strings:
		$0 = {60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01}
	condition:
		$0 at pe.entry_point
}