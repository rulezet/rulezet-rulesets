import "pe"
rule _GEM_Image_graphics_file_
{
	meta:
		description = "GEM Image graphics file"
	strings:
		$0 = {00 01 00 08 00 04 00 02}
	condition:
		$0 at pe.entry_point
}