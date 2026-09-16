import "pe"
rule _Sharp_GPB_Graphics_format_
{
	meta:
		description = "Sharp GPB Graphics format"
	strings:
		$0 = {4D 00 00 00 00 ?? ?? ?? ?? 08 00 00 00 03 00 00}
	condition:
		$0 at pe.entry_point
}