rule _WinUpack_v030_beta__By_Dwing_
{
	meta:
		description = "WinUpack v0.30 beta -> By Dwing"
	strings:
		$0 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00}
		$1 = {E9 ?? ?? ?? ?? 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02}
	condition:
		$0 or $1
}