import "pe"
rule _Zortech_C_200_1_
{
	meta:
		description = "Zortech C 2.00 (1)"
	strings:
		$0 = {FA B8 00 00 05 0F 00 B9 04 00 D3 E8 8C C9 03 C1 8E D8 8C 06 00 00 26 8B 1E 2C 00 89 1E 47 01 8B D8 2B 1E 00 00 89 1E AD 00 26 8B 1E 02 00 2B D8 81 FB 00 10 72 03 BB FF 0F 8B D0 03 D3 42 B1 04 D3 E3 8E D0 8B E3 81 EB 00 00 80 FF 02 73 06 BA}
	condition:
		$0 at pe.entry_point
}