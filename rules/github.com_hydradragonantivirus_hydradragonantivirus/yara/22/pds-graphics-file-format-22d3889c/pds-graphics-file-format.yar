import "pe"
rule _PDS_graphics_file_format_
{
	meta:
		description = "PDS graphics file format"
	strings:
		$0 = {49 4D 41 47 45 49 44 45 4E 54 49 46 49 45 52 20}
	condition:
		$0 at pe.entry_point
}