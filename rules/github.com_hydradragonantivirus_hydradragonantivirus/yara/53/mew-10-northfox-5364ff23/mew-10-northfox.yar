import "pe"
rule _MEW_10__Northfox_
{
	meta:
		description = "MEW 10 - Northfox"
	strings:
		$0 = {33 C0 E9}
	condition:
		$0 at pe.entry_point
}