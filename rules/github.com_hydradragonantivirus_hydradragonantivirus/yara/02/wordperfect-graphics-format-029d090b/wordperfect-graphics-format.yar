import "pe"
rule _WordPerfect_Graphics_format_
{
	meta:
		description = "WordPerfect Graphics format"
	strings:
		$0 = {FF 57 50 43 10 00 00 00}
	condition:
		$0 at pe.entry_point
}