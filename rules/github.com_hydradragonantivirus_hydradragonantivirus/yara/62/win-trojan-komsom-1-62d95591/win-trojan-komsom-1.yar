rule Win_Trojan_Komsom_1
{
strings:
	$a0 = { 83ee0350b47acd213ca77511e9de00524546736f6674014b6f6d736f6d5351520e8d84ed0050560633ffb449cd21b4 }


condition:
	$a0
}