rule Win_Trojan_Gergano_2
{
strings:
	$a0 = { ffb93000f3a4e985fd5e81c60001bf0001b92c01f3a4 }


condition:
	$a0
}