import "pe"
rule _CorelPhotoPaint_Image_
{
	meta:
		description = "CorelPhotoPaint Image"
	strings:
		$0 = {43 50 54 37 46 49 4C 45}
	condition:
		$0 at pe.entry_point
}