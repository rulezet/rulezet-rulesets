import "pe"
rule stnpe113
{
	meta:
		author = "PEiD"
		description = "Stone's PE Encryptor 1.13"
		group = "177"
		function = "0"
	strings:
		$a0 = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }
	condition:
		$a0 at pe.entry_point
}