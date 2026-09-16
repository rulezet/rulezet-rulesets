import "pe"
rule _XWD_graphics_format_
{
	meta:
		description = "XWD graphics format"
	strings:
		$0 = {00 00 00 71 00 00 00 07 00 00 00 02 00 00 00}
	condition:
		$0 at pe.entry_point
}