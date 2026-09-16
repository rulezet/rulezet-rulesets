rule Win_Trojan_Lovgate_27
{
strings:
	$a0 = { b3b21911aa803c46eecd92690d8cd060b1ac1656ebc65a44b1b20d95 }


condition:
	$a0
}