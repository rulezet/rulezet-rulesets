import "pe"
rule _CrypteXeC_09_
{
	meta:
		description = "CrypteXeC 0.9"
	strings:
		$0 = {8B EC FA C7 46 F7 40 07 42 81 FA BD F3 75 F9 FF 66 F7 08 42 BE 27 1F 5B CC C2 C5 74 4B A3 A3 DB 93 1F C9 A6 C9 3A 7A 27 9F 38 F1 99 67 22 85 50 55 9C 23 39 77 85 94 34 E5 18 F9 06 A3 3E FA C4 3A 69 04 E8 09 AC 5F 97 EE D8 BE DA 05 00 06 99}
	condition:
		$0 at pe.entry_point
}