rule Win_Trojan_Career_3
{
strings:
	$a0 = { 80fc11741b80fc1274163dcdab75059df8ca02003d004b }


condition:
	$a0
}