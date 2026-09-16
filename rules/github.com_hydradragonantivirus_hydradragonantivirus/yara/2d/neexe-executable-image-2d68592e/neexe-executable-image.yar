import "pe"
rule _NEExe_Executable_Image_
{
	meta:
		description = "NE-Exe Executable Image"
	strings:
		$0 = {4E 45}
	condition:
		$0 at pe.entry_point
}