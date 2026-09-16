import "pe"
rule _WinZip_SFX_
{
	meta:
		description = "WinZip SFX"
	strings:
		$0 = {8A CB D3 E7 4F FF 4D D8 0F B7 08 23 FE 3B F9 75 E4 E9 9F FD FF FF FF 45 EC 8B 45 EC 39 45 E0 0F 8D 7F FD FF FF 83 7D DC 00 74 32 83 7D E0 01 74 2C B8 01 00 00 00 EB 27 83 7D D8 00 74 0E FF B5 38 FF FF FF E8 1D 00 00 00 83 C4 04 68 00 00 40}
	condition:
		$0 at pe.entry_point
}