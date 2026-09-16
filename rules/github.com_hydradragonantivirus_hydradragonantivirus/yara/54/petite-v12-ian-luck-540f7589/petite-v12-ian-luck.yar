import "pe"
rule _PEtite_v12__Ian_Luck_
{
	meta:
		description = "PEtite v1.2 -> Ian Luck"
	strings:
		$0 = {9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00}
	condition:
		$0 at pe.entry_point
}