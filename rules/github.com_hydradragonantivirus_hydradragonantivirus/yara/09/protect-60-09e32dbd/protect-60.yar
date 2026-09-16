import "pe"
rule _Protect_60_
{
	meta:
		description = "Protect! 6.0"
	strings:
		$0 = {1E B4 30 CD 21 3C 02 73 02 CD 20 BE 00 00 E8 18 00 E8 08 00 1F 8C D8 8E C0 E9 15 00 BB 00 00 B4 00 AC 04 00 AA 4B 75 F9 C3 0E 1F FC 0E 07 8B FE C3}
	condition:
		$0 at pe.entry_point
}