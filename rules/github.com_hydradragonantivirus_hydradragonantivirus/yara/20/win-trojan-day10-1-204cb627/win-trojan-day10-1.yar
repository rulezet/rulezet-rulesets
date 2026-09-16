rule Win_Trojan_Day10_1
{
strings:
	$a0 = { 8134c80bade2f945bd000943d59faf6dbfccc6d279e299cc1bef37f87dda27f85b42cfcc0aef37da7dca27da999081 }


condition:
	$a0
}