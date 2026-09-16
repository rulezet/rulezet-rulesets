import "pe"
rule _Rose_Tiny_102_
{
	meta:
		description = "Rose Tiny 1.02"
	strings:
		$0 = {EB 01 EA 06 1E 1E 52 B8 4D 30 CD 21 86 C4 3D FE 02 73 02 CD 20 52 BA EB 04 5A EB FB 9A 0E 1F E8 02 00 24 24 5A B4 09 CD 21 52 BA EB 04 5A EB FB 9A EB 02 D8 88 5A 1F FA CD 11 8B EC 8B 46 FA 05 0B 00 FF E0 81 EB 03 EA EB F0 81 46 FA 1A 00 83}
	condition:
		$0 at pe.entry_point
}