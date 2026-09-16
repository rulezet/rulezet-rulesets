import "pe"
rule penguin
{
	meta:
		author = "PEiD"
		description = "PEnguinCrypt 1.0 -> Pingvin"
		group = "151"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? 55 50 67 64 FF 36 ?? ?? 67 64 89 26 ?? ?? BD 4B 48 43 42 B8 04 ?? ?? ?? CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 ?? ?? 58 5D BB ?? ?? 40 ?? 33 C9 33 C0 32 0C 03 40 81 F8 ?? 01 ?? ?? 75 F4 }
	condition:
		$a0 at pe.entry_point
}