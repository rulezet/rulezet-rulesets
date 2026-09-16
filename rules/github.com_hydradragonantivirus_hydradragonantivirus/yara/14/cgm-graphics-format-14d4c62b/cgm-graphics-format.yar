import "pe"
rule _CGM_Graphics_format_
{
	meta:
		description = "CGM Graphics format"
	strings:
		$0 = {00 2A 08 48 69 4A 61 61 6B 20 32}
	condition:
		$0 at pe.entry_point
}