import "pe"
rule _aPack_090_COM_
{
	meta:
		description = "aPack 0.90 [COM]"
	strings:
		$0 = {8C C8 80 C4 10 8E C0 FC B9 00 00 BE 00 01 8B FE 57 F3 A5 5F BE 00 01 06 68 20 01 1E 07 8E D8 CB 06 57 B2 80 BD 00 01 50 A4 FF D5 73 FB FF D5 73 14 FF D5 73 00 33 DB B1 04 FF D5 13 DB E2 FA 75 00 93 AA EB E4 E8 00 00 49 E2 07 5B 53 E8 00 00}
	condition:
		$0 at pe.entry_point
}