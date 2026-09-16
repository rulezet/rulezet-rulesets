import "pe"
rule exefog_112
{
	meta:
		author = "PEiD"
		description = "EXEFog 1.12"
		group = "444"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 90 EB 04 01 07 01 07 BB ?? ?? ?? ?? B9 C8 03 00 00 B0 ?? 30 04 0B 8A 04 0B E2 F8 E8 00 00 00 5D DE }
	condition:
		$a0 at pe.entry_point
}