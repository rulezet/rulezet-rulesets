import "pe"
rule _PEExe_Executable_Image_
{
	meta:
		description = "PE-Exe Executable Image"
	strings:
		$0 = {50 45 00 00}
	condition:
		$0 at pe.entry_point
}