import "pe"
rule _NsPacK_V30__LiuXingPing_
{
	meta:
		description = "NsPacK V3.0 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? ?? ?? 66 8B 06 66 83 F8 00 74}
	condition:
		$0 at pe.entry_point
}