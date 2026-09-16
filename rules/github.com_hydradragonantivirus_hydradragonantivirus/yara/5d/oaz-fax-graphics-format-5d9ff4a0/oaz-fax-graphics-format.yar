import "pe"
rule _OAZ_Fax_Graphics_format_
{
	meta:
		description = "OAZ Fax Graphics format"
	strings:
		$0 = {0F 0F 0F 0F 01 00 00 00}
	condition:
		$0 at pe.entry_point
}