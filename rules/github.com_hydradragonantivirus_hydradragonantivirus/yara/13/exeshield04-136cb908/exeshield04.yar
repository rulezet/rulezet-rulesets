import "pe"
rule exeshield04
{
	meta:
		author = "PEiD"
		description = "EXE Shield 0.4 -> SMoKE"
		group = "116"
		function = "0"
	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B2 0A 00 00 EB 01 00 8D 8D F8 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 }
	condition:
		$a0 at pe.entry_point
}