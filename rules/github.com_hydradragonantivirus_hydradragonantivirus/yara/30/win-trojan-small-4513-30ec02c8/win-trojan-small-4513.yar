rule Win_Trojan_Small_4513
{
strings:
	$a0 = { b82196e70f2d2164a50f5050e8??000000e8 }


condition:
	$a0
}