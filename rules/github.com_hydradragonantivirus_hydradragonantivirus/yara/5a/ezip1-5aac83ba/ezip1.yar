import "pe"
rule ezip1
{
	meta:
		author = "PEiD"
		description = "EZIP 1.0 -> Jonathan Clark"
		group = "121"
		function = "0"
	strings:
		$a0 = { E9 19 32 ?? ?? E9 7C 2A ?? ?? E9 19 24 ?? ?? E9 FF 23 ?? ?? E9 1E 2E ?? ?? E9 88 2E ?? ?? E9 2C }
	condition:
		$a0 at pe.entry_point
}