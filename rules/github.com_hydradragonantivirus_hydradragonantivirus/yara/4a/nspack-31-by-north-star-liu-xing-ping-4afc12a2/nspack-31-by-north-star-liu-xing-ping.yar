import "pe"
rule _NsPack_31_by_North_Star_Liu_Xing_Ping_
{
	meta:
		description = "NsPack 3.1 by North Star (Liu Xing Ping)"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5}
	condition:
		$0 at pe.entry_point
}