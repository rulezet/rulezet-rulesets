import "pe"
rule _Visual_Studio_NET_2003_Hotfix_Custom_
{
	meta:
		description = "Visual Studio .NET 2003 Hotfix Custom"
	strings:
		$0 = {6A 60 68 E8 87 00 01 E8 37 14 00 00 BF 94 00 00 00 8B C7 E8 B3 05 00 00 89 65 E8 8B F4 89 3E 56 FF 15 14 10 00 01 8B 4E 10 89 0D 58 22 01 01 8B 46 04 A3 64 22 01 01 8B 56 08 89 15 68 22 01 01}
	condition:
		$0 at pe.entry_point
}