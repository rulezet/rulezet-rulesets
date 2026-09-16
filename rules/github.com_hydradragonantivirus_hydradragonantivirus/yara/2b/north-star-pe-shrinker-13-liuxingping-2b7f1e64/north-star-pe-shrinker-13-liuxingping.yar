import "pe"
rule _North_Star_PE_Shrinker_13__Liuxingping_
{
	meta:
		description = "North Star PE Shrinker 1.3 -> Liuxingping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5}
	condition:
		$0 at pe.entry_point
}