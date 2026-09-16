import "pe"
rule neolite1x
{
	meta:
		author = "PEiD"
		description = "Neolite 1.0 - 1.01 -> Neoworx Inc."
		group = "130"
		function = "0"
	strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 35 ?? ?? ?? ?? 50 FF 25 }
	condition:
		$a0 at pe.entry_point
}