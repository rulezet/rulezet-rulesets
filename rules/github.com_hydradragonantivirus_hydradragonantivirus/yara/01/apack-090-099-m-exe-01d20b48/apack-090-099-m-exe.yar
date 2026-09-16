import "pe"
rule _aPack_090__099_m_EXE_
{
	meta:
		description = "aPack 0.90 - 0.99 -m [EXE]"
	strings:
		$0 = {1E 06 8C C8 8E D8 05 00 00 8E C0 50 BE 00 00 33 FF FC B2 80 BD 00 00 33 C9 50 A4}
	condition:
		$0 at pe.entry_point
}