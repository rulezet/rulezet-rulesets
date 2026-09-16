import "pe"
rule _JEDMICS_CCITT4_Graphics_format_
{
	meta:
		description = "JEDMICS CCITT4 Graphics format"
	strings:
		$0 = {80 00 00 00 ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}