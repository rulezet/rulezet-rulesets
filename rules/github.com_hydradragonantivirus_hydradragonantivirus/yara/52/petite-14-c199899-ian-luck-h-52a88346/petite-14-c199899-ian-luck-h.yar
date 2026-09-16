import "pe"
rule _Petite_14__c199899_Ian_Luck_h_
{
	meta:
		description = "Petite 1.4 -> (c)1998-99 Ian Luck (h)"
	strings:
		$0 = {66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC}
	condition:
		$0 at pe.entry_point
}