import "pe"
rule pmaster16
{
	meta:
		author = "PEiD"
		description = "Pack Master 1.0 (PEX Clone) -> WebtoolMaster"
		group = "134"
		function = "0"
	strings:
		$a0 = { 60 E8 01 ?? ?? ?? E8 83 C4 04 E8 01 ?? ?? ?? E9 5D 81 ED D3 22 40 ?? E8 04 02 ?? ?? E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
	condition:
		$a0 at pe.entry_point
}