import "pe"
rule nullsoft14
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP 1.x"
		group = "24"
		function = "0"
	strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 }
	condition:
		$a0 at pe.entry_point
}