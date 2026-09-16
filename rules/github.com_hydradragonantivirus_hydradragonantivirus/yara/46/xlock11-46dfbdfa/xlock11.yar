import "pe"
rule xlock11
{
	meta:
		author = "PEiD"
		description = "XCR 0.11 -> X-Lock"
		group = "192"
		function = "0"
	strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }
	condition:
		$a0 at pe.entry_point
}