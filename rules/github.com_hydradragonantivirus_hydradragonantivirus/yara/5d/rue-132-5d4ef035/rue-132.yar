import "pe"
rule _RUE_132_
{
	meta:
		description = "RUE 1.32"
	strings:
		$0 = {68 00 01 60 BF 03 01 B9 00 00 B0 00 2E 30 05 FE C0 47 E2 F8 61 C7 06 00 01 E9 00 C6 06 02 01 00 C3 48 69 6E 74 3A 20 27 00 27 20 77 61 73 20 63 6F 6E 76 65 72 74 65 64 20 75 73 69 6E 67 20 52 4F 53 45 27 73 20 52 55 45 21 20 73 55 4D 73 44}
	condition:
		$0 at pe.entry_point
}