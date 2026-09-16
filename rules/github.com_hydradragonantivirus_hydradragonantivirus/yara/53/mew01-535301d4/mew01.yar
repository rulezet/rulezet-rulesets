rule mew01
{
	meta:
		author = "PEiD"
		description = "MEW 5 0.1 beta -> NorthFox/HCC"
		group = "444"
		function = "0"
	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 ?? ?? 01 00 ?? ?? ?? 00 00 10 40 00 }
	condition:
		$a0
}