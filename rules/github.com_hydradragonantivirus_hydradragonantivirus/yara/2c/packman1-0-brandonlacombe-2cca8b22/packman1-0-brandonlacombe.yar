rule Packman1_0__BrandonLaCombe
{
	meta:
		author = "PEiD"
		description = "Packman 1.0 -> Brandon LaCombe"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }
	condition:
		$a0
}