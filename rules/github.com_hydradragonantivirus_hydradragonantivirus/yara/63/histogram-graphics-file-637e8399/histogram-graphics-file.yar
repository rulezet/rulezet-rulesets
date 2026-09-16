import "pe"
rule _Histogram_graphics_file_
{
	meta:
		description = "Histogram graphics file"
	strings:
		$0 = {6D 68 77 61 6E 68 00 04 01 02 01 02}
	condition:
		$0 at pe.entry_point
}