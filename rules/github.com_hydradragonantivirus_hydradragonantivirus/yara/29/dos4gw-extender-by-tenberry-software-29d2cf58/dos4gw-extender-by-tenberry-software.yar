import "pe"
rule _DOS4GW_Extender_by_Tenberry_Software_
{
	meta:
		description = "DOS/4GW Extender by Tenberry Software"
	strings:
		$0 = {BF 00 00 8E D7 81 C4 0E 12 BE BD 01 2B F7 8B C6 B1 04 D3 E0 48 36 A3 E6 0C 36 89 26 DC 0C BE 23 0F 46 89 36 02 00 8C C3 2B DE F7 DB B4 4A CD 21 36 8C 1E EC 0C 16 07 FC BF 86 11 B9}
	condition:
		$0 at pe.entry_point
}