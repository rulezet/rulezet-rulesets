import "pe"
rule _PNG_Graphics_format_
{
	meta:
		description = "PNG Graphics format"
	strings:
		$0 = {89 50 4E 47 0D 0A 1A 0A}
	condition:
		$0 at pe.entry_point
}