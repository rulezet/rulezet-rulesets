import "pe"
rule _aPack_090__099_ds_EXE_
{
	meta:
		description = "aPack 0.90 - 0.99 -d/-s [EXE]"
	strings:
		$0 = {8C CB BA 00 00 03 DA FC 33 F6 33 FF 4B 8E DB 8D 87 00 00 8E C0 B9 08 00 F3 A5 4A 75 EB 8E C3 8E D8 33 FF BE 2E 00 05 00 00 0E 50 6A 00 CB}
	condition:
		$0 at pe.entry_point
}