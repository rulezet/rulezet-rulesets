rule Win_Trojan_Small_4360
{
strings:
	$a0 = { b808010070c1c81250505b535f }


condition:
	$a0
}