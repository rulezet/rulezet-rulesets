import "pe"
rule pelock_10h
{
	meta:
		author = "PEiD"
		description = "PELock 1.0x Heuristic Mode -> Bartosz Wojcik"
		group = "147"
		function = "0"
	strings:
		$a0 = { 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 56 69 72 74 75 61 6C 41 6C 6C 6F 63 ?? 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }
	condition:
		$a0 at pe.entry_point
}