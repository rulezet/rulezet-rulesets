import "pe"
rule _UCEXE_v23_v24_
{
	meta:
		description = "UCEXE v2.3, v2.4"
	strings:
		$0 = {50 1E 0E 1F FC 33 F6 E8 ?? ?? 16 07 33 F6 33 FF B9 ?? ?? F3 A5 06 B8 ?? ?? 50 CB}
	condition:
		$0 at pe.entry_point
}