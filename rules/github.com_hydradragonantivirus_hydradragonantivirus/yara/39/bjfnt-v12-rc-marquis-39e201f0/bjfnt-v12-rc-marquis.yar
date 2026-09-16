import "pe"
rule _BJFnt_v12_RC__MARQUiS_
{
	meta:
		description = ".BJFnt v1.2 RC -> :MARQUiS:"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB}
	condition:
		$0 at pe.entry_point
}