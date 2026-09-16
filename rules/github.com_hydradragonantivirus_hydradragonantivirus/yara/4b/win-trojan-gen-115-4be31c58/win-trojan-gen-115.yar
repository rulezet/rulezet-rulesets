rule Win_Trojan_Gen_115
{
strings:
	$a0 = { a602ba0000e83c002ec70687019319e85b00b440b91800ba7501e82700b801572e8b0e6f01 }


condition:
	$a0
}