rule _Shrinker_33_
{
	meta:
		description = "Shrinker 3.3"
	strings:
		$0 = {00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8}
	condition:
		$0
}