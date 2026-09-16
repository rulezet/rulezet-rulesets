import "pe"
rule _aPack_058__074_2_EXE_
{
	meta:
		description = "aPack 0.58 - 0.74 (2) [EXE]"
	strings:
		$0 = {1E 06 8C C8 8E D8 05 00 00 8E C0 BE 00 00 33 FF FC B6 01 BD}
	condition:
		$0 at pe.entry_point
}