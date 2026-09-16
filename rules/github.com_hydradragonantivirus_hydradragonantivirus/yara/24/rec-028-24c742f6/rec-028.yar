import "pe"
rule _Rec_028_
{
	meta:
		description = "Rec 0.28"
	strings:
		$0 = {06 1E 52 B8 02 30 1E CD 21 86 E0 3D FE 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 EB 02 D8 88 1F 5A B4 30 CD 21 3C 02 73 02 CD 20 BF 01 02 8B 03 90 2B F7 90 BF 06 07 B9 01 02 FB 1E B8 40 00 8E D8 A1 6C 00 3B 06 6C 00 74 FA 1F 53}
	condition:
		$0 at pe.entry_point
}