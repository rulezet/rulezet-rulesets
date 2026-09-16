rule Win_Trojan_Kohn6_2
{
strings:
	$a0 = { 4c31908b072bc189074343034c33903bdf7ef0eb0a }


condition:
	$a0
}