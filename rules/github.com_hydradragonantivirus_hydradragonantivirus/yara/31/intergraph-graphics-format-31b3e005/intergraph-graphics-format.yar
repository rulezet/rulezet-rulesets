import "pe"
rule _InterGraph_Graphics_format_
{
	meta:
		description = "InterGraph Graphics format"
	strings:
		$0 = {08 09 FE 01 18 00 00 00}
	condition:
		$0 at pe.entry_point
}