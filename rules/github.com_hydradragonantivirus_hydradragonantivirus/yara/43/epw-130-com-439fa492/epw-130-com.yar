import "pe"
rule _EPW_130_COM_
{
	meta:
		description = "EPW 1.30 [COM]"
	strings:
		$0 = {06 57 1E 56 55 52 51 53 50 BB 03 00 81 C3 00 01 2E 8B 07 8C CB 03 C3 83 C0 10 50 B8 D1 00 50 CB 8C C0 83 C0 10 8E C0 83 C0 05 8E D8 2E 8B 0E 00 00 2B F6 2B FF FC F3 A4 0E 1F BA 1E 00 B4 09 CD 21 BB 0E 00 B9 10 00 B4 00 CD 16 3C 0D 74 09 3C}
	condition:
		$0 at pe.entry_point
}