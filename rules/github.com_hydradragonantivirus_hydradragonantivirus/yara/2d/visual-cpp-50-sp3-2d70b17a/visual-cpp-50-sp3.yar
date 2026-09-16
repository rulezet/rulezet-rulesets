import "pe"
rule _Visual_Cpp_50_SP3_
{
	meta:
		description = "Visual C++ 5.0 SP3"
	strings:
		$0 = {55 8B EC 6A FF 68 00 00 40 00 68 00 00 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 98 53 56 57 89 65 E8 C7 45 FC 00 00 00 00 6A 02 FF 15 00 00 40 00 83 C4 04 C7 05 00 00 40 00 FF FF FF FF C7 05 00 00 40 00 FF FF FF FF FF 15 00 00}
	condition:
		$0 at pe.entry_point
}