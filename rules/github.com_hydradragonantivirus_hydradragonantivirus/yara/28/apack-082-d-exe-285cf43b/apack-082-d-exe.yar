import "pe"
rule _aPack_082_d_EXE_
{
	meta:
		description = "aPack 0.82 -d [EXE]"
	strings:
		$0 = {8C CB BA 00 00 03 DA 8D 87 00 00 FC 33 F6 33 FF 48 4B 8E C0 8E DB B9 08 00 F3 A5 4A 75 EE 8E C3 8E D8 33 FF BE 2F 00 05 00 00 0E 50 6A 00 CB}
	condition:
		$0 at pe.entry_point
}