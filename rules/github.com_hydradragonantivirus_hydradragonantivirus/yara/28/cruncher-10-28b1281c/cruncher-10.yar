import "pe"
rule _Cruncher_10_
{
	meta:
		description = "Cruncher 1.0"
	strings:
		$0 = {2E 8C 1E 00 00 2E A3 02 00 B4 30 CD 21 3C 03 73 12 BB 51 00 8E DB 8D 16 B4 00 B4 09 CD 21 06 33 C0 50 CB BB 51 00 8E C3 BF B3 00 8B 1E 2C 00 0B DB 74 DE 8E DB BE 00 00 83 3C 00 74 03 46 EB F8 83 C6 04 AC AA 0A C0 75 FA BB 51 00 8E C3 8E DB}
	condition:
		$0 at pe.entry_point
}