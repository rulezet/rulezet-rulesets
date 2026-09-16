import "pe"
rule _Rec_033a_
{
	meta:
		description = "Rec 0.33a"
	strings:
		$0 = {06 1E 52 B8 16 30 1E CD 21 86 C4 3D FF 02 73 02 CD 20 B4 09 0E 1F E8 02 00 24 24 5A CD 21 EB 02 D8 88 1F 5A B4 30 CD 21 3C 03 73 02 CD 20 3C 03 73 02 33 C0 BF 08 08 8B 08 90 2B F7 90 BF 08 08 B9 08 08 52 BA EB 04 5A EB FB 9A EB 2E FE 20 E7}
	condition:
		$0 at pe.entry_point
}