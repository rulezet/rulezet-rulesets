import "pe"
rule _MacPaint_Graphics_format_
{
	meta:
		description = "MacPaint Graphics format"
	strings:
		$0 = {00 00 00 02 FF FF FF FF}
	condition:
		$0 at pe.entry_point
}