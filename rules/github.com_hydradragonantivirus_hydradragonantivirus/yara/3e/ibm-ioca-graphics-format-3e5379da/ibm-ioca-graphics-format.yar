import "pe"
rule _IBM_IOCA_Graphics_format_
{
	meta:
		description = "IBM IOCA Graphics format"
	strings:
		$0 = {00 11 D3 A6 FB}
	condition:
		$0 at pe.entry_point
}