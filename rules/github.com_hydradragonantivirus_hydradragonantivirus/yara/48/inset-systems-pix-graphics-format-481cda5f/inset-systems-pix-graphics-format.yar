import "pe"
rule _Inset_Systems_PIX_Graphics_format_
{
	meta:
		description = "Inset Systems PIX Graphics format"
	strings:
		$0 = {03 00 ?? 00 00 00 20 00}
	condition:
		$0 at pe.entry_point
}