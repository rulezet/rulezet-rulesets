import "pe"
rule _Rec_Small_102a_
{
	meta:
		description = "Rec Small 1.02a"
	strings:
		$0 = {8C D8 1E E8 00 00 83 C0 0F 5D B9 00 00 81 ED EB 03 40 8E D8 2B DB B2 00 00 17 FE C2 43 83 FB 10 75 F6 E2 ED 1F 8C C0 03 C3 2E 01 86 25 04 2E 03 86 29 04 FA 2E 8B A6 27 04 8E D0 EB 00 EA}
	condition:
		$0 at pe.entry_point
}