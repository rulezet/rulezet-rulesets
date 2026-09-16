import "pe"
rule _RLPack_v118_Basic_aPLib_
{
	meta:
		description = "RLPack v1.18 Basic [aPLib"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83}
	condition:
		$0 at pe.entry_point
}