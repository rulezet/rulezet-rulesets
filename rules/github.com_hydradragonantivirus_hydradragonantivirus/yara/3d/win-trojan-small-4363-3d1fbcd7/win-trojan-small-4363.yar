rule Win_Trojan_Small_4363
{
strings:
	$a0 = { b808010070e9??00000039c1 }


condition:
	$a0
}