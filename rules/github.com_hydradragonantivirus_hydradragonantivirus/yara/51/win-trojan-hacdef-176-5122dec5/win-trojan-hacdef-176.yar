rule Win_Trojan_Hacdef_176
{
strings:
	$a0 = { e85b69ffff506a008b45e8508b45ec5068ff010f00575653e80f83ffff }


condition:
	$a0
}