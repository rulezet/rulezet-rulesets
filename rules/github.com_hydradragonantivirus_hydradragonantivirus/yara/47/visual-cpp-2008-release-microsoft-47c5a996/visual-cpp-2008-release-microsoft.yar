import "pe"
rule _Visual_Cpp_2008_Release__Microsoft_
{
	meta:
		description = "Visual C++ 2008 Release -> Microsoft"
	strings:
		$0 = {E8 ?? ?? ?? ?? E9 A4 FE FF FF}
	condition:
		$0 at pe.entry_point
}