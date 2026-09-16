import "pe"
rule _PCC_12_
{
	meta:
		description = "PCC 1.2"
	strings:
		$0 = {36 8C 1E 00 00 A1 02 00 8C D3 2B C3 77 03 E9 D3 00 48 3D 00 10 72 03 B8 FF 0F B1 04 D3 E0 3B C4 73 03 E9 BF 00 36 8B 1E 00 00 36 03 1E 02 00 83 C3 7F 3B E3 75 02 8B E0 36 89 26 00 00 B4 30 CD 21 3C 02 72 06 36 C6 06 00 00 01 C6 06 FF 00 0D}
	condition:
		$0 at pe.entry_point
}