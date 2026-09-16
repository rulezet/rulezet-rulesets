rule Win_Trojan_Look_4
{
strings:
	$a0 = { 020055c044000100ffff990e000037060000080000001403 }


condition:
	$a0
}