rule _ORiEN_V1XV2X__Fisun_AV__Sign_by_fly_
{
	meta:
		description = "ORiEN V1.X-V2.X -> Fisun A.V. ! Sign by fly"
	strings:
		$0 = {4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D}
	condition:
		$0
}