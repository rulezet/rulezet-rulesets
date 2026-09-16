rule peidb102
{
	meta:
		author = "PEiD"
		description = "PEiD-Bundle 1.02 -> BoB / Team PEiD"
		group = "2003"
		function = "0"
	strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 ?? ?? ?? 2E ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }
	condition:
		$a0
}