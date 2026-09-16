rule Win_Trojan_Loz_2
{
strings:
	$a0 = { 83c71a90b900072e00052c2d47e2f8 }


condition:
	$a0
}