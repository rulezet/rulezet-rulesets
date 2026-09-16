rule upackmutanter_01
{
	meta:
		author = "PEiD"
		description = "Upack-Mutanter 0.1 -> Spirit"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE B0 11 40 00 AD EB 3A 76 34 EB 7C 48 01 ?? ?? ?? ?? ?? 6F 61 64 4C 69 62 ?? ?? ?? ?? ?? 00 00 18 10 00 00 10 00 00 00 00 ?? ?? 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 EB CC 00 00 3A 00 04 00 50 FF 76 34 EB F2 }
	condition:
		$a0
}