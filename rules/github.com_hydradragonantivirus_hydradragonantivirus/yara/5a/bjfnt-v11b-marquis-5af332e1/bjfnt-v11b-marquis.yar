import "pe"
rule _BJFnt_v11b__MARQUiS_
{
	meta:
		description = ".BJFnt v1.1b -> :MARQUiS:"
	strings:
		$0 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56}
	condition:
		$0 at pe.entry_point
}