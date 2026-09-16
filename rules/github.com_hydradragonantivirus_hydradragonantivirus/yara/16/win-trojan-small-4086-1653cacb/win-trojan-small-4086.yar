rule Win_Trojan_Small_4086
{
strings:
	$a0 = { eb35cd2d6a00ff11e84500000089f929e9c3 }


condition:
	$a0
}