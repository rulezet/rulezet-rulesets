import "pe"
rule _BJFnt_v13_
{
	meta:
		description = ".BJFnt v1.3"
	strings:
		$0 = {EB 3A 1E EB CD 20 9C EB CD 20 EB CD 20 60}
		$1 = {60 06 FC 1E 07 BE 6A 04 68 10}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}