rule Win_Trojan_Small_4364
{
strings:
	$a0 = { b808010070c1c812508d5c20008d7c }


condition:
	$a0
}