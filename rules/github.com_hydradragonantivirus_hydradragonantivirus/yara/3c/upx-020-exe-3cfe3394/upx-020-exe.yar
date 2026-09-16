import "pe"
rule _UPX_020_EXE_
{
	meta:
		description = "UPX 0.20 [EXE]"
	strings:
		$0 = {8C CB B9 00 00 BE 00 00 89 F7 1E A9 B5 80 8D 87 05 00 8E D8 05 00 00 8E C0 FD F3 A5 FC 2E 80 6C 13 10 73 E8 AF AD 0E 0E 0E 06 1F 07 16 68 00 00 BD FF FF F7 E1 93 CB 55 50 58 21 03 03 02 07}
	condition:
		$0 at pe.entry_point
}