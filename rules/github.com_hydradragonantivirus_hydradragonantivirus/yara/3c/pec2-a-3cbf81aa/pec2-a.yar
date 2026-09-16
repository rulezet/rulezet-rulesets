import "pe"
rule pec2_a
{
	meta:
		author = "PEiD"
		description = "PECompact 2.00 alpha 38 -> Jeremy Collake"
		group = "139"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? 01 74 7A C6 80 ?? ?? ?? ?? 01 9C 55 53 51 57 52 56 8D 98 ?? ?? ?? ?? 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 }
	condition:
		$a0 at pe.entry_point
}