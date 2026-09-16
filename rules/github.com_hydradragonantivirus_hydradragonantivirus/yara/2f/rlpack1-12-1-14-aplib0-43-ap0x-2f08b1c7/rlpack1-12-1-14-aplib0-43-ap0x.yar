rule RLPack1_12_1_14_aPlib0_43___ap0x
{
	meta:
		author = "PEiD"
		description = "RLPack 1.12-1.14 (aPlib 0.43) -> ap0x"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF EB 0F FF ?? ?? ?? FF ?? ?? ?? D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }
	condition:
		$a0
}