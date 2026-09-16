import "pe"
rule _RLPack_V118_Basic_Edition_LZMA_430__ap0x_
{
	meta:
		description = "RLPack V1.18 Basic Edition (LZMA 4.30) -> ap0x"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00}
	condition:
		$0 at pe.entry_point
}