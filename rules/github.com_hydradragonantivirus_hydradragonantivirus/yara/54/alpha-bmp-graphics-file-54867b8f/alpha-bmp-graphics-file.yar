import "pe"
rule _Alpha_BMP_graphics_file_
{
	meta:
		description = "Alpha BMP graphics file"
	strings:
		$0 = {FF FF 00 01 64 00 00 00}
	condition:
		$0 at pe.entry_point
}