import "pe"
rule exeshield02b
{
	meta:
		author = "PEiD"
		description = "EXE Shield 0.2b -> SMoKE"
		group = "116"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED 90 19 40 00 EB 01 00 8D B5 1A 1A 40 00 BA 1E 0A 00 00 EB 01 00 8D 8D 38 24 40 00 8B 09 E8 14 00 00 00 83 EB 01 }
	condition:
		$a0 at pe.entry_point
}