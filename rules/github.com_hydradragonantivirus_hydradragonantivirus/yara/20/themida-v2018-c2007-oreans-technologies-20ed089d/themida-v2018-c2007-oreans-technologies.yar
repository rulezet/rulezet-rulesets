import "pe"
rule _Themida_v2018__c2007_Oreans_Technologies_
{
	meta:
		description = "Themida v2.0.18 -> (c)2007 Oreans Technologies"
	strings:
		$0 = {83 EC 04 50 53 E8 00 00 00 00 58 8B D8 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}