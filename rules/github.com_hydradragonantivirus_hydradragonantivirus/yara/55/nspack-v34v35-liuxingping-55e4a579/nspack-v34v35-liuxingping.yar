import "pe"
rule _NsPacK_V34V35__LiuXingPing_
{
	meta:
		description = "NsPacK V3.4-V3.5 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? ?? ?? 80 38 01 0F 84}
	condition:
		$0 at pe.entry_point
}