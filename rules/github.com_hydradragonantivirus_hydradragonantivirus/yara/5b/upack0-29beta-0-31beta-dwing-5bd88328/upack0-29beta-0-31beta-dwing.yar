import "pe"
rule Upack0_29Beta_0_31Beta__Dwing
{
	meta:
		author = "PEiD"
		description = "Upack 0.29 Beta - 0.31 Beta -> Dwing"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }
	condition:
		$a0 at pe.entry_point
}