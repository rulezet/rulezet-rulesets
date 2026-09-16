rule Win_Trojan_Gen_33
{
strings:
	$a0 = { 4e01eacd21c3b44fcd21c35133c03b86 }


condition:
	$a0
}