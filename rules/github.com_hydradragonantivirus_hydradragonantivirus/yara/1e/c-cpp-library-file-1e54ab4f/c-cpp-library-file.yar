import "pe"
rule _C_Cpp_Library_file_
{
	meta:
		description = "C, C++ Library file"
	strings:
		$0 = {F0 0D 00 00}
	condition:
		$0 at pe.entry_point
}