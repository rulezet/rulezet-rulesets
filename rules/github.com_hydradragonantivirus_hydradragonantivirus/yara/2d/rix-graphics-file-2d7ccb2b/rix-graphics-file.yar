import "pe"
rule _RIX_graphics_file_
{
	meta:
		description = "RIX graphics file"
	strings:
		$0 = {52 49 58 33}
	condition:
		$0 at pe.entry_point
}