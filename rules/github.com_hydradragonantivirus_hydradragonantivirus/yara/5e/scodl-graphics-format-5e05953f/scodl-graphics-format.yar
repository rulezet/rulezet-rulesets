import "pe"
rule _Scodl_Graphics_format_
{
	meta:
		description = "Scodl Graphics format"
	strings:
		$0 = {E0 01 ?? 00 ?? ?? 00}
	condition:
		$0 at pe.entry_point
}