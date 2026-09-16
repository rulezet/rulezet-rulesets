rule Win_Trojan_Small_5411
{
strings:
	$a0 = { b85900000083f85975f6 }


condition:
	$a0
}