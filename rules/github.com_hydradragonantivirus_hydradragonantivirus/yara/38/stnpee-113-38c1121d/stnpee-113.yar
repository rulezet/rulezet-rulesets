import "pe"
rule _STNPEE_113_
{
	meta:
		description = "STNPEE 1.13"
	strings:
		$0 = {55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00}
	condition:
		$0 at pe.entry_point
}