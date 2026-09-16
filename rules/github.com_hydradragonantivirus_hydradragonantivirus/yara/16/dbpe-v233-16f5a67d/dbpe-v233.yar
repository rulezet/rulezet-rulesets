import "pe"
rule _DBPE_v233_
{
	meta:
		description = "DBPE v2.33"
	strings:
		$0 = {EB 20 40 9C 55 57 56 52 51 53 9C E8 5D 81}
	condition:
		$0 at pe.entry_point
}