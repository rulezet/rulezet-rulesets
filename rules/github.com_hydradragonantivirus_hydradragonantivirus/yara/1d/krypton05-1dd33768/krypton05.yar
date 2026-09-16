import "pe"
rule krypton05
{
	meta:
		author = "PEiD"
		description = "Krypton 0.5 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 54 E8 ?? ?? ?? ?? 5D 8B C5 81 ED 71 44 ?? ?? 2B 85 64 60 ?? ?? EB 43 DF }
	condition:
		$a0 at pe.entry_point
}