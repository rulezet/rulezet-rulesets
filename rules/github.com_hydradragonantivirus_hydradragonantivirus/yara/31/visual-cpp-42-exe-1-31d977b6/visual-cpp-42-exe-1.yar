import "pe"
rule _Visual_Cpp_42_EXE__1_
{
	meta:
		description = "Visual C++ 4.2 (EXE - 1)"
	strings:
		$0 = {64 A1 00 00 00 00 55 8B EC 6A FF 68 00 00 00 00 68 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 00 53 56 57 89 65 E8 C7 45 FC 00 00 00 00 6A 00 FF 15 00 00 00 00 83 C4 04 C7 05 00 00 00 00 FF FF FF FF A1 00 00 00 00 A3 00 00 00 00 FF 15 00 00}
	condition:
		$0 at pe.entry_point
}