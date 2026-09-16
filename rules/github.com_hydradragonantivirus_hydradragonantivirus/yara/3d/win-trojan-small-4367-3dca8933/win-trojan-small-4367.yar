rule Win_Trojan_Small_4367
{
strings:
	$a0 = { b808010070c1c8125089c3 }


condition:
	$a0
}