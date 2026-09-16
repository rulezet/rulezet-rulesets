import "pe"
rule _MEW_11_SE_10__Northfox_
{
	meta:
		description = "MEW 11 SE 1.0 -> Northfox"
	strings:
		$0 = {E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00}
	condition:
		$0 at pe.entry_point
}