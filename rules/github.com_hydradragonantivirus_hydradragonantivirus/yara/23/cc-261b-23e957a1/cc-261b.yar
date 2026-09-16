import "pe"
rule _CC_261b_
{
	meta:
		description = "CC 2.61b"
	strings:
		$0 = {BA 00 00 B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB B9 EB 09 B8 05 FE EB FC 80 C4 3B EB F4 8D 9D 29 01 CD 21 B0 01 CD 21 EB 02 EB FE E8 00 00 5B C6 47 06 82 B0 80 E6 21 BB 20 FF BE 50 01 8B FB B9 B6 00 F3 A4 8B C3 C1 E8 04 8C CD 03 C5 50 51 CB}
	condition:
		$0 at pe.entry_point
}