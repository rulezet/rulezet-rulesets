rule Win_Trojan_Halloechen_1
{
strings:
	$a0 = { c7065b005555ba4900c706fb003000e8a1feff064a01 }


condition:
	$a0
}