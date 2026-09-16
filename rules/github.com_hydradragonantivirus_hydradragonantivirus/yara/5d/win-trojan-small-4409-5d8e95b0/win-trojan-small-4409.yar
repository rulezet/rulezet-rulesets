rule Win_Trojan_Small_4409
{
strings:
	$a0 = { 56575355e8a4000000e93200000085c0 }


condition:
	$a0
}