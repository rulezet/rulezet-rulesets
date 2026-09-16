import "pe"
rule _XE_Executable_Image_using_DOSExtender_
{
	meta:
		description = "XE Executable Image (using DOSExtender)"
	strings:
		$0 = {58 45}
	condition:
		$0 at pe.entry_point
}