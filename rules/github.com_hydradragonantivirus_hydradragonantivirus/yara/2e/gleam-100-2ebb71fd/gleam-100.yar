import "pe"
rule _Gleam_100_
{
	meta:
		description = "Gleam 1.00"
	strings:
		$0 = {83 EC 0C 53 56 57 E8 24 02 00}
	condition:
		$0 at pe.entry_point
}