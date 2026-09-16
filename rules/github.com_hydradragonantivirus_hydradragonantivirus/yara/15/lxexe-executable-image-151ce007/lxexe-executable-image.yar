import "pe"
rule _LXExe_Executable_Image_
{
	meta:
		description = "LX-Exe Executable Image"
	strings:
		$0 = {4C 58}
	condition:
		$0 at pe.entry_point
}