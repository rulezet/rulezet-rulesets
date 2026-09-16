rule Win_Trojan_Gergano_1
{
strings:
	$a0 = { b93000f3a4e9c6fd5e81c60001bf0001b9de00f3a4 }


condition:
	$a0
}