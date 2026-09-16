import "pe"
rule _MEW_5_10__Northfox_
{
	meta:
		description = "MEW 5 1.0 -> Northfox"
	strings:
		$0 = {BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0}
	condition:
		$0 at pe.entry_point
}