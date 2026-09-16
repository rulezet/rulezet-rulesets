rule RLPack1_15_1_17Dll__ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.15-1.17 Dll -> ap0x"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }
	condition:
		$a0
}