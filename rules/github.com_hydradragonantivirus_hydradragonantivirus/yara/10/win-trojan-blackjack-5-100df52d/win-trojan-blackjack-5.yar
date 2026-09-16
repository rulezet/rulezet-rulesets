rule Win_Trojan_BlackJack_5
{
strings:
	$a0 = { b92000cd210bc07403e98c00b42f }


condition:
	$a0
}