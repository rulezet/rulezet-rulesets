import "pe"
rule _Micrografix_Draw_Graphics_format_
{
	meta:
		description = "Micrografix Draw Graphics format"
	strings:
		$0 = {01 FF 02 04 03 02 00 02}
	condition:
		$0 at pe.entry_point
}