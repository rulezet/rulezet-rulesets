import "pe"
rule pcs045
{
	meta:
		author = "PEiD"
		description = "PC Shrinker 0.45 -> Virogen"
		group = "137"
		function = "0"
	strings:
		$a0 = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
	condition:
		$a0 at pe.entry_point
}