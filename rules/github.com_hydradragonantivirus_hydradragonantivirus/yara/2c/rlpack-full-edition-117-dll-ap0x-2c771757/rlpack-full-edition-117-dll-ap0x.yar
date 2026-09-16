import "pe"
rule _RLPack_Full_Edition_117_DLL__Ap0x_
{
	meta:
		description = "RLPack Full Edition 1.17 DLL -> Ap0x"
	strings:
		$0 = {80 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? ?? ?? 8D 9D ?? ?? ?? ?? 33 FF E8}
	condition:
		$0 at pe.entry_point
}