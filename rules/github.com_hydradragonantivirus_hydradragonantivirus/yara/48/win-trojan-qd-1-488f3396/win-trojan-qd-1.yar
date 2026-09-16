rule Win_Trojan_QD_1
{
strings:
	$a0 = { fd83c732b92000f3a4bf00018bf583 }


condition:
	$a0
}