import "pe"
rule _WebCops_EXE__LINK_Data_Security_
{
	meta:
		description = "WebCops [EXE] -> LINK Data Security"
	strings:
		$0 = {EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72}
	condition:
		$0 at pe.entry_point
}