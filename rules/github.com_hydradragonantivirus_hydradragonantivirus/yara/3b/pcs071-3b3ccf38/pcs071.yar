import "pe"
rule pcs071
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.71 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { 9C 60 BD ?? ?? ?? ?? 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D ?? ?? ?? ?? 89 85 }
	condition:
		$a0 at pe.entry_point
}