import "pe"
rule _Visual_Cpp_2005_DLL__Microsoft_
{
	meta:
		description = "Visual C++ 2005 DLL -> Microsoft"
	strings:
		$0 = {8B FF 55 8B EC 83 7D 0C 01}
	condition:
		$0 at pe.entry_point
}