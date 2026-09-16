import "pe"
rule _NsPack_v31__North_Star_h_
{
	meta:
		description = "NsPack v3.1 -> North Star (h)"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? FF FF 8A 03 3C 00 74 10 8D 9D ?? ?? FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 ?? ?? FF FF 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00}
	condition:
		$0 at pe.entry_point
}