rule gm11
{
	meta:
		author = "PEiD"
		description = "Goat's PE Mutilator 1.1"
		group = "124"
		function = "0"
	strings:
		$a0 = { E8 EB 0B 00 00 00 00 00 }
	condition:
		$a0
}