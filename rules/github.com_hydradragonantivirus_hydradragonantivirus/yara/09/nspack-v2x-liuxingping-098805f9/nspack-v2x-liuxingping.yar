rule _nSpack_V2x__LiuXingPing_
{
	meta:
		description = "nSpack V2.x -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5}
	condition:
		$0
}