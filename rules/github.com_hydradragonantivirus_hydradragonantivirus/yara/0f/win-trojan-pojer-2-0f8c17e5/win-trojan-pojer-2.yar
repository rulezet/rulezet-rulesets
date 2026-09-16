rule Win_Trojan_Pojer_2
{
strings:
	$a0 = { 5ef583ee0af5bb260003def52e8a943607f5b90f072e3017f543e2f9 }


condition:
	$a0
}