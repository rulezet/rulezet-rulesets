import "pe"
rule _PMODEW_121_
{
	meta:
		description = "PMODE/W 1.21"
	strings:
		$0 = {FC 16 07 BF 00 01 8B F7 57 B9 05 13 F3 A5 06 1E 07 1F 5F BE 1D 02 06 0E A4 AD 8B E8 B2 10 1E B8 D4 01 50 CB D1 ED FE CA 75 05 AD 8B E8 B2 10 C3 E8 F1 FF 73 0F E8 EC FF 80 D1 01 D0 E1 E8 E4 FF D0 D7 E2 F9 B6 02 B1 04 FE C6 E8 D7 FF 72 1D E2}
	condition:
		$0 at pe.entry_point
}