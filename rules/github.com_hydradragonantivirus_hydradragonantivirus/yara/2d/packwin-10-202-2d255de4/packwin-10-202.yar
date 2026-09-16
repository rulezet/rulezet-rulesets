import "pe"
rule _PackWin_10_202_
{
	meta:
		description = "PackWin 1.0?- 2.02"
	strings:
		$0 = {8C C0 FA 8E D0 BC FE 00 FB 06 0E 1F 2E 8B 0E 0C 00 8B F1 4E 8B FE 8C DB 2E 03 1E 0A 00 8E C3 FD F3 A4 53 B8 38 00 50 CB 2E 8B 2E 08 00 8C DA 8B C5 3D 00 10 76 03 B8 00 10 2B E8 2B D0 2B D8 8E DA 8E C3 B1 03 D3 E0 8B C8 D1 E0 48 48 8B F0 8B}
	condition:
		$0 at pe.entry_point
}