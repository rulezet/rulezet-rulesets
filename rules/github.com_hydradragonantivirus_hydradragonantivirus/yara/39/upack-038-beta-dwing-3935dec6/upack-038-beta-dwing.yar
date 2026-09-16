import "pe"
rule _Upack_038_beta__Dwing_
{
	meta:
		description = "Upack 0.38 beta -> Dwing"
	strings:
		$0 = {BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}