import "pe"
rule CodeVeil1_2R5465__XheoInc_
{
	meta:
		author = "PEiD"
		description = "CodeVeil 1.2 R5465 -> Xheo Inc."
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E9 29 01 00 00 8D 49 00 44 25 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 43 56 31 30 2D 35 44 56 47 42 36 45 2D 32 4A 36 58 49 2D 32 48 4E 35 4A 2D 32 55 58 32 31 2D 47 55 57 48 42 }
	condition:
		$a0 at pe.entry_point
}