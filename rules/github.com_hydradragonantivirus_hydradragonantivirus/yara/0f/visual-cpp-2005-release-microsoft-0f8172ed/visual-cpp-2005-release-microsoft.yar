import "pe"
rule _Visual_Cpp_2005_Release__Microsoft_
{
	meta:
		description = "Visual C++ 2005 Release -> Microsoft"
	strings:
		$0 = {E8 ?? ?? ?? ?? E9 ?? FD FF FF}
	condition:
		$0 at pe.entry_point
}