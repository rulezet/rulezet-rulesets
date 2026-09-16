import "pe"
rule _Unpack_20_
{
	meta:
		description = "Un�pack 2.0"
	strings:
		$0 = {9C BA 00 00 2D 00 00 81 E1 00 00 81 F3 00 00 B4 00 9D 50 B8 00 00 BA 00 00 05 00 00 3B 06 02 00 72 2A B4 09 BA 1C 01 CD 21 B8 01 4C CD 21 4E 6F 74 20 65 6E 6F 75 67 68 20 6D 65 6D 6F 72 79 24 20 20 20 20 20 20 20 B9 00 00 2B FF 57 BE 54 01}
	condition:
		$0 at pe.entry_point
}