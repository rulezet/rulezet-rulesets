import "pe"
rule _MSCC_10_
{
	meta:
		description = "MSCC 1.0"
	strings:
		$0 = {0E 07 BE 00 00 BF 00 01 B9 05 00 F3 A4 B9 64 02 BE 10 01 AC CC 98 03 D8 E2 F9 FA 53 50 58 4C 4C 5B 3B C3 5B FB 74 02 FA F4 1E 33 C0 8E D8 F7 16 05 00 EB 01 9A F7 16 05 00 1F 50 58 4C 4C 5B 3B C3 75 7A B9 00 00 BE 05 01 BF 05 01 B3 00 FE C3}
	condition:
		$0 at pe.entry_point
}