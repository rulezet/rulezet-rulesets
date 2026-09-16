import "pe"
rule _RLPack_119_Basic_Edition_
{
	meta:
		description = "RLPack 1.19 Basic Edition"
	strings:
		$0 = {60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 ?? ?? 00 00 EB 0C}
	condition:
		$0 at pe.entry_point
}