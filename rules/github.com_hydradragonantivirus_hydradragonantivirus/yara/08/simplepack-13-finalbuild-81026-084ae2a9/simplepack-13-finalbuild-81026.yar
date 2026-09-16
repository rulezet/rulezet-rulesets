import "pe"
rule _SimplePack_13_FinalBuild_81026_
{
	meta:
		description = "SimplePack 1.3 Final[Build 81026"
	strings:
		$0 = {4D 5A 90 EB 01 00 52 E9 62 01 00 00 50 45 00 00 4C 01 01 00 00 00 00}
	condition:
		$0 at pe.entry_point
}