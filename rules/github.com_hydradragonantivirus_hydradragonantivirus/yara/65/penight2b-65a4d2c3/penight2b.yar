import "pe"
rule penight2b
{
	meta:
		author = "PEiD"
		description = "PENightMare 2 Beta -> FreddyK"
		group = "150"
		function = "0"
	strings:
		$a0 = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }
	condition:
		$a0 at pe.entry_point
}