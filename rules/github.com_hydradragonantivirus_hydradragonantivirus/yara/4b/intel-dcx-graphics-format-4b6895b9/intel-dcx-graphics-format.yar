import "pe"
rule _Intel_DCX_Graphics_format_
{
	meta:
		description = "Intel DCX Graphics format"
	strings:
		$0 = {B1 68 DE 3A 04 10 00}
	condition:
		$0 at pe.entry_point
}