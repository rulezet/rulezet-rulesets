import "pe"
rule _AutoLogic_Graphics_format_
{
	meta:
		description = "AutoLogic Graphics format"
	strings:
		$0 = {FF 04 00 07}
	condition:
		$0 at pe.entry_point
}