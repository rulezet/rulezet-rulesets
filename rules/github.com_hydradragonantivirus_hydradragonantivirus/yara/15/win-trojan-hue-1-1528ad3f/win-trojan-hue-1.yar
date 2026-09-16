rule Win_Trojan_Hue_1
{
strings:
	$a0 = { cd213cdc746ba102002d3f00a302008ec08bf583ee03 }


condition:
	$a0
}