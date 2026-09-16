import "pe"
rule _Visual_Cpp_2003_DLL__Microsoft_
{
	meta:
		description = "Visual C++ 2003 DLL -> Microsoft"
	strings:
		$0 = {8B FF 55 8B EC}
	condition:
		$0 at pe.entry_point
}