import "pe"
rule _HelpEXE_12_
{
	meta:
		description = "HelpEXE 1.2"
	strings:
		$0 = {FA 2E 8C 16 00 00 2E 89 26 00 00 8C C8 8E D0 8D 06 DC 00 89 C4 FB FC BE 81 00 AC 3C 20 74 FB 3C 3F 74 24 3C 2F 75 05 AC 3C 3F 74 1B 8C D8 05 10 00 2E 01 06 00 00 FA 2E 8E 16 00 00 2E 8B 26 00 00 FB 2E FF 2E 00 00 0E 1F BA 00 00 B4 09 CD 21}
	condition:
		$0 at pe.entry_point
}