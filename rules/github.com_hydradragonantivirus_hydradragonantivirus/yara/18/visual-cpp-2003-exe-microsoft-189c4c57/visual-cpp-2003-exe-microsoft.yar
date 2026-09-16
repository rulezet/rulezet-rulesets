import "pe"
rule _Visual_Cpp_2003_EXE__Microsoft_
{
	meta:
		description = "Visual C++ 2003 EXE -> Microsoft"
	strings:
		$0 = {6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 FF 57}
	condition:
		$0 at pe.entry_point
}