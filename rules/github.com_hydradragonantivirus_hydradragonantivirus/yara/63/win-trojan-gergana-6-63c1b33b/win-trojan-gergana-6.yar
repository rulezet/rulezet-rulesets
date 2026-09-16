rule Win_Trojan_Gergana_6
{
strings:
	$a0 = { fd5e81c60001bf0001b92c01f3a4 }


condition:
	$a0
}