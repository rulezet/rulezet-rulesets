rule Win_Trojan_V_89
{
strings:
	$a0 = { 0233d2b440cd218b160c008b0e0e0081c22e0083d100 }


condition:
	$a0
}