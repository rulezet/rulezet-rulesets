import "pe"
rule bjfnt12rc
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.2rc -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }
	condition:
		$a0 at pe.entry_point
}