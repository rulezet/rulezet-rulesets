import "pe"
rule _LGLZ_103b__104b_
{
	meta:
		description = "LGLZ 1.03b - 1.04b"
	strings:
		$0 = {FC 1E 06 0E 8C C8 01 06 34 01 BA 00 00 03 C2 8B D8 05 00 00 8E DB 8E C0 33 F6 33 FF B9 08 00 F3 A5 4B 48 4A 79 EE 8E C3 8E D8 BE 46 00 AD 95 B2 10 EA}
	condition:
		$0 at pe.entry_point
}