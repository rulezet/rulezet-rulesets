import "pe"
rule krypton03
{
	meta:
		author = "PEiD"
		description = "Krypton 0.3 -> Yado/Lockless"
		group = "129"
		function = "0"
	strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }
	condition:
		$a0 at pe.entry_point
}