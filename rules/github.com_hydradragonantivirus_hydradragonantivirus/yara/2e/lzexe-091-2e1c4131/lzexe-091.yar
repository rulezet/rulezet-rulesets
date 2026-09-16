import "pe"
rule _LZEXE_091_
{
	meta:
		description = "LZEXE 0.91"
	strings:
		$0 = {50 06 0E 1F 8B 0E 0C 00 8B F1 4E 89 F7 8C DB 03 1E 0A 00 8E C3 FD F3 A4 53 B8 00 00 50 CB 2E 8B 2E 08 00 00 DA 89 E8 3D 00 10 76 03 B8 00 10 29 C5 29 C2 29 C3 8E DA 8E C3 B1 03 D3 E0 89 C1}
	condition:
		$0 at pe.entry_point
}