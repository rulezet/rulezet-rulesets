import "pe"
rule _Microsoft_Visual_Cpp_v71_EXE_
{
	meta:
		description = "Microsoft Visual C++ v7.1 EXE"
	strings:
		$0 = {6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01}
	condition:
		$0 at pe.entry_point
}