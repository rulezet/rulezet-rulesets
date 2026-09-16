rule gm16
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.6"
		group = "999"
		function = "0"
	strings:
		$a0 = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }
	condition:
		$a0
}