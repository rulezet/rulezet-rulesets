import "pe"
rule vbox43
{
	meta:
		author = "PEiD"
		description = "VBOX 4.3 - 4.6.x -> WeijunLi"
		group = "185"
		function = "0"
	strings:
		$a0 = { 55 8B EC 83 C4 E8 56 57 BE ?? ?? ?? ?? 8B 45 08 89 46 4C FF 75 0C 8F 46 50 8B 45 10 89 46 54 56 E8 ?? 00 00 00 5F 5E C9 C2 0C 00 }
	condition:
		$a0 at pe.entry_point
}