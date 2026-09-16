rule Win_Trojan_Small_4362
{
strings:
	$a0 = { b808010070[0-255]c1c81250505b535f535eb9a0080000 }


condition:
	$a0
}