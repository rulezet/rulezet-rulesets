import "pe"
rule _BINLock_10_
{
	meta:
		description = "BINLock 1.0"
	strings:
		$0 = {31 C0 8E C0 26 C7 06 04 00 64 01 26 8C 0E 06 00 26 C7 06 0C 00 46 01 26 8C 0E 0E 00 2E C7 06 0A 00 33 01 2E 8C 0E 0C 00 CC CD 01 EB CD B9 00 00 BF 00 00 B8 00 41 8E C0 B0 00 F3 AA B4 4C CD 21 B8 BB 01 BB 64 01 29 D8 89 C1 BE 64 01 2E 8A 14}
	condition:
		$0 at pe.entry_point
}