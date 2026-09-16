import "pe"
rule _RJ_Crush_110_
{
	meta:
		description = "RJ Crush 1.10"
	strings:
		$0 = {06 FC 8C C8 BA 00 00 03 D0 52 BA 00 00 52 BA 00 00 03 C2 8B D8 05 00 00 8E DB 8E C0 33 F6 33 FF B9 08 00 F3 A5 4B 48 4A 79 EE 8E D8 8E C3 BE 47 00 AD 8B E8 B2 10 CB FF}
	condition:
		$0 at pe.entry_point
}