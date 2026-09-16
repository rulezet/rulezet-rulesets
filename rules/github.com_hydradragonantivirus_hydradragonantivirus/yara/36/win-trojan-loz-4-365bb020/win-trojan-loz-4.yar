rule Win_Trojan_Loz_4
{
strings:
	$a0 = { 83c71a90b9ee0a2e3005047c47e2f8 }


condition:
	$a0
}