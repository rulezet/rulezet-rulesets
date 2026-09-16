rule Win_Trojan_Angelina_1
{
strings:
	$a0 = { f901750580fc027403e995009c2eff1e84017303e9a7002681bff00081c67503 }


condition:
	$a0
}