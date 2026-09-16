import "pe"
rule execryptor151
{
	meta:
		author = "PEiD"
		description = "EXECryptor 1.5.1 -> SoftComplete Developement"
		group = "120"
		function = "0"
	strings:
		$a0 = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }
	condition:
		$a0 at pe.entry_point
}