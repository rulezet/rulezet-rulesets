import "pe"
rule _Cracked_by_AutoHack_1_
{
	meta:
		description = "Cracked by AutoHack (1)"
	strings:
		$0 = {FA 50 51 57 56 1E 06 2E 80 3E ?? ?? ?? 74 ?? 8E 06 ?? ?? 2B FF FC}
	condition:
		$0 at pe.entry_point
}