import "pe"
rule _QuickLink_II_Fax_Graphics_format_
{
	meta:
		description = "QuickLink II Fax Graphics format"
	strings:
		$0 = {51 4C 49 49 46 41 58 20}
	condition:
		$0 at pe.entry_point
}