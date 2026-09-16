rule Win_Trojan_XA_2
{
strings:
	$a0 = { 0ee80000fa8bec5832c0894602814600 }


condition:
	$a0
}