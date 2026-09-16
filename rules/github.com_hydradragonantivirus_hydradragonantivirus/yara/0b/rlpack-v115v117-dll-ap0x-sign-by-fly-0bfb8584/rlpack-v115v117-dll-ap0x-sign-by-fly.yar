import "pe"
rule _RLPack_V115V117_Dll__ap0x__Sign_by_fly_
{
	meta:
		description = "RLPack V1.15-V1.17 Dll -> ap0x ! Sign by fly"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8}
	condition:
		$0 at pe.entry_point
}