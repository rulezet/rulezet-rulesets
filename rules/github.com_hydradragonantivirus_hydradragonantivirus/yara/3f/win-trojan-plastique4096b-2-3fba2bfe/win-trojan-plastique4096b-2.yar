rule Win_Trojan_Plastique4096B_2
{
strings:
	$a0 = { 42bf00012e8b8d1400be001003f7 }


condition:
	$a0
}