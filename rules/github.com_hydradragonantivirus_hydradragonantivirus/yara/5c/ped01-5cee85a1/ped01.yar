import "pe"
rule ped01
{
	meta:
		author = "PEiD"
		description = "PEDiminisher 0.1 -> Teraphy"
		group = "143"
		function = "0"
	strings:
		$a0 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B ?? ?? ?? 89 95 9A 33 40 ?? 80 BD 99 }
	condition:
		$a0 at pe.entry_point
}