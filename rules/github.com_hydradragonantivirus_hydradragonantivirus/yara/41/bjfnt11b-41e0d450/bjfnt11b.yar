rule bjfnt11b
{
	meta:
		author = "PEiD"
		description = ".BJFNT 1.1b -> :MARQUiS:"
		group = "107"
		function = "0"
	strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }
	condition:
		$a0
}