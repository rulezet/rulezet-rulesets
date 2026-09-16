import "pe"
rule Upack0_32beta__Dwing
{
	meta:
		author = "PEiD"
		description = "Upack 0.32 beta -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }
	condition:
		$a0 at pe.entry_point
}