import "pe"
rule _by_Central_Point_Software_
{
	meta:
		description = "by Central Point Software"
	strings:
		$0 = {50 51 52 56 57 8B EB 1E 2E}
	condition:
		$0 at pe.entry_point
}