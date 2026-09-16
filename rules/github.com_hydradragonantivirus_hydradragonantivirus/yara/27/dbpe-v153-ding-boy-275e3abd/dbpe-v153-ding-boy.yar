import "pe"
rule _DBPE_v153__Ding_Boy_
{
	meta:
		description = "DBPE v1.53 -> Ding Boy"
	strings:
		$0 = {9C 55 57 56 52 51 53 9C FA E8 ?? ?? ?? ?? 5D 81 ED 5B 53 40 ?? B0 ?? E8 ?? ?? ?? ?? 5E 83 C6 11 B9 27 ?? ?? ?? 30 06 46 49 75 FA}
	condition:
		$0 at pe.entry_point
}