rule _nSpack_V23__LiuXingPing_
{
	meta:
		description = "nSpack V2.3 -> LiuXingPing"
	strings:
		$0 = {9C 60 70 61 63 6B 24 40}
	condition:
		$0
}