import "pe"
rule _eXpressor_v11__CGSoftLabs_
{
	meta:
		description = "eXpressor v1.1 -> CGSoftLabs"
	strings:
		$0 = {E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00}
	condition:
		$0 at pe.entry_point
}