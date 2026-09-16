import "pe"
rule _RLPack_v114_beta__ap0x_
{
	meta:
		description = "RLPack v1.14 beta -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 67 02 00 00 8D 9D 2E 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 3B 00}
	condition:
		$0 at pe.entry_point
}