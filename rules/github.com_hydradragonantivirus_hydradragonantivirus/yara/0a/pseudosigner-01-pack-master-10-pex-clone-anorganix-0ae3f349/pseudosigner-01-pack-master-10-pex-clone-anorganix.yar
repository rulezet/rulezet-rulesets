import "pe"
rule _PseudoSigner_01_Pack_Master_10_PEX_Clone__Anorganix_
{
	meta:
		description = "PseudoSigner 0.1 [Pack Master 1.0 (PEX Clone)] --> Anorganix"
	strings:
		$0 = {60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}