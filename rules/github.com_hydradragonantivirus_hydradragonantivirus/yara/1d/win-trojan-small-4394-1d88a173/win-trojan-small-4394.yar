rule Win_Trojan_Small_4394
{
strings:
	$a0 = { b8010100d8c1c812e9 }


condition:
	$a0
}