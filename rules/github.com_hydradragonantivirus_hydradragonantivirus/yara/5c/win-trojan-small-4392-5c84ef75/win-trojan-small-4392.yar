rule Win_Trojan_Small_4392
{
strings:
	$a0 = { b8010100d8c1c81250 }


condition:
	$a0
}