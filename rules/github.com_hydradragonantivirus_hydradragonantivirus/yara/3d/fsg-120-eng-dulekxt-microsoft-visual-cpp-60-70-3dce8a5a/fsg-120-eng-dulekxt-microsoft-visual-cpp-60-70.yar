import "pe"
rule _FSG_120_Eng__dulekxt__Microsoft_Visual_Cpp_60__70_
{
	meta:
		description = "FSG 1.20 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)"
	strings:
		$0 = {EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA}
	condition:
		$0 at pe.entry_point
}