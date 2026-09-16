import "pe"
rule _PEtite_v13__Ian_Luck_
{
	meta:
		description = "PEtite v1.3 -> Ian Luck"
	strings:
		$0 = {66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 68 ?? ?? ?? ?? 53 50 80 04 24 08 50 80 04 24 42}
	condition:
		$0 at pe.entry_point
}