import "pe"
rule _TPCs_COM_scrambler_100_
{
	meta:
		description = "TPC's COM scrambler 1.00"
	strings:
		$0 = {3E C6 06 08 01 FD 90 EB 03 00 00 00 2E 8A 36 09 01 8E C0 8C D8 BE 4F 01 BF 77 01 2E 03 3E 0A 01 26 A3 06 00 26 89 3E 04 00 26 A3 0E 00 26 C7 06 0C 00 61 01 0E 07 B9 32 00 FC F3 A4 CC BE 77 01 BF 00 01 2E 8B 0E 0A 01 B8 00 01 0E 50 CD 01 58}
	condition:
		$0 at pe.entry_point
}