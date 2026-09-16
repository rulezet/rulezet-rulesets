import "pe"
rule _Crypt_17_COM_
{
	meta:
		description = "Crypt 1.7 [COM]"
	strings:
		$0 = {0E 17 9C 58 F6 C4 01 74 03 EB 4C 90 B4 01 BE 24 01 BF FF FD B9 81 00 68 00 01 68 A5 01 68 00 00 57 F3 A4 C3 B0 02 E6 21 60 B8 99 01 33 FF 8E C7 BF 0C 00 AB 8C C8 AB BB 6C 04 B8 3A FE BF 04 00 26 C6 07 00 AB 8C C8 AB 26 80 3F 00 75 09 2E 9C}
	condition:
		$0 at pe.entry_point
}