rule Win_Trojan_Small_4368
{
strings:
	$a0 = { b808010070e9080000005050 }


condition:
	$a0
}