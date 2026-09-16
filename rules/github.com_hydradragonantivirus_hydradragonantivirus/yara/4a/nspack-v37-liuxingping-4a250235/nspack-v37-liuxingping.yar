import "pe"
rule _NsPacK_V37__LiuXingPing_
{
	meta:
		description = "NsPacK V3.7 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D ?? ?? ?? ?? ?? 80 39 01 0F ?? ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}