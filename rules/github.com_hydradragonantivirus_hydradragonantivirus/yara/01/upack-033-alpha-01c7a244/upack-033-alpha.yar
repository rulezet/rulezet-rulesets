rule upack_033_alpha
{
	meta:
		author = "PEiD"
		description = "Upack 0.33 alpha -> Dwing"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE E8 11 40 00 AD 50 AD 50 66 BE 58 01 6A 12 BF ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 B1 04 F3 AB C1 E0 0A B5 10 F3 AB BF ?? ?? ?? ?? E9 ?? ?? ?? ?? 47 65 74 50 }
	condition:
		$a0
}