import "pe"
rule _ExeSmasher_
{
	meta:
		description = "ExeSmasher"
	strings:
		$0 = {9C FE 03 00 60 BE 00 00 41 00 8D BE 00 10 FF FF 57 83 CD FF EB 10}
	condition:
		$0 at pe.entry_point
}