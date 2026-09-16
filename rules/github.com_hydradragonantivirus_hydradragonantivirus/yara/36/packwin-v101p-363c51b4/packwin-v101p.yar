import "pe"
rule _PACKWIN_v101p_
{
	meta:
		description = "PACKWIN v1.01p"
	strings:
		$0 = {8C C0 FA 8E D0 BC ?? ?? FB 06 0E 1F 2E ?? ?? ?? ?? 8B F1 4E 8B FE 8C DB 2E ?? ?? ?? ?? 8E C3 FD F3 A4 53 B8 ?? ?? 50 CB}
	condition:
		$0 at pe.entry_point
}