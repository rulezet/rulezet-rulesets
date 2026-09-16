import "pe"
rule _Docmaker_120_
{
	meta:
		description = "Docmaker 1.20"
	strings:
		$0 = {B4 0F CD 10 06 1E 3C 03 76 06 3C 07 74 09 EB 42 B8 00 B8 8E C0 EB 05 B8 00 B0 8E C0 BF 00 00 8C C8 8E D8 BE 40 01 B4 0B B7 00 8A 1E 3D 01 CD 10 8A 3E 3E 01 B8 00 06 31 C9 BA 50 19 CD 10 FC B9 80 07 AC AA 47 E2 FB 1F 07 B4 02 31 DB BA 00 17}
	condition:
		$0 at pe.entry_point
}