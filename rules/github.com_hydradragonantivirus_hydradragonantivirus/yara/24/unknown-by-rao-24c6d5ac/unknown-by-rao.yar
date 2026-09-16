import "pe"
rule _unknown_by_RAO_
{
	meta:
		description = "unknown by RAO"
	strings:
		$0 = {8B C4 2D A6 02 24 00 8B F8 57 B9 53 00 BE 14 01 F3 A5 FD C3 97 4F 4F B9 00 00 03 F1 D1 E9 F3 A5 FC E8 91 00 8D 75 02 BF 00 01 3C A4 E8 80 00 72 FA E8 77 00 AC 93 B7 FF 73 65 E8 72 00 D0 D7 E8 6D 00 72 12 B6 02 E8 66 00 72 09 E8 61 00 D0 D7}
	condition:
		$0 at pe.entry_point
}