import "pe"
rule _Imaging_Technology_Graphics_format_
{
	meta:
		description = "Imaging Technology Graphics format"
	strings:
		$0 = {49 4D 00 00}
	condition:
		$0 at pe.entry_point
}