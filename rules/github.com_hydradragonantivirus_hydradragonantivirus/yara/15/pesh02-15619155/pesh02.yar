import "pe"
rule pesh02
{
	meta:
		author = "PEiD"
		description = "PESHiELD 0.2 / 0.2b / 0.2b2 -> ANAKiN"
		group = "157"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }
	condition:
		$a0 at pe.entry_point
}