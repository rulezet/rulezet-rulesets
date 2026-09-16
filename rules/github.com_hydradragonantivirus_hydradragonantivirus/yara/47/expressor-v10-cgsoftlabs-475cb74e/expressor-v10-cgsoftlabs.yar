import "pe"
rule _eXPressor_V10__CGSoftLabs_
{
	meta:
		description = "eXPressor V1.0 -> CGSoftLabs"
	strings:
		$0 = {E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00}
	condition:
		$0 at pe.entry_point
}