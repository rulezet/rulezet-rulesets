import "pe"
rule _AVHRR_Graphics_format_
{
	meta:
		description = "AVHRR Graphics format"
	strings:
		$0 = {D5 C8 00 01 00 03 00 01}
	condition:
		$0 at pe.entry_point
}