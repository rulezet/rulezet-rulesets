rule Win_Trojan_Gergana_9
{
strings:
	$a0 = { fd5e81c60001bf0001b9c201f3a4 }


condition:
	$a0
}