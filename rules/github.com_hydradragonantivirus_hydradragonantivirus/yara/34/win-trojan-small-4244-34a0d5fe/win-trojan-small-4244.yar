rule Win_Trojan_Small_4244
{
strings:
	$a0 = { 60e8000000005a6629 }


condition:
	$a0
}