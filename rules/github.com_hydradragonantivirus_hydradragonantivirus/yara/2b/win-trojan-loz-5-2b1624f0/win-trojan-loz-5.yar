rule Win_Trojan_Loz_5
{
strings:
	$a0 = { 8bfe83c71a90b9f40a2e3005041d47e2f8 }


condition:
	$a0
}