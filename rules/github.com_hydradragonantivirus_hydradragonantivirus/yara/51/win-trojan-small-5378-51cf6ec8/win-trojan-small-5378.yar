rule Win_Trojan_Small_5378
{
strings:
	$a0 = { b808010070c1c8125089c3e947 }


condition:
	$a0
}