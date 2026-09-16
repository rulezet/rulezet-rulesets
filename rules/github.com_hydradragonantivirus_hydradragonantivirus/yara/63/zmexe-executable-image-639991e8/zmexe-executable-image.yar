import "pe"
rule _ZMExe_Executable_Image_
{
	meta:
		description = "ZM-Exe Executable Image"
	strings:
		$0 = {5A 4D}
	condition:
		$0 at pe.entry_point
}