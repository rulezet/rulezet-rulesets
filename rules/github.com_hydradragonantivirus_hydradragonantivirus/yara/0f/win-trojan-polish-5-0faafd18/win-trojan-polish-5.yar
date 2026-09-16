rule Win_Trojan_Polish_5
{
strings:
	$a0 = { 03fc8bf283c60a90bf00 }


condition:
	$a0
}