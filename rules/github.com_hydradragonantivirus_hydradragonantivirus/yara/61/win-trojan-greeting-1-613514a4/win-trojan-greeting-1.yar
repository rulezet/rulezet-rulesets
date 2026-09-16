rule Win_Trojan_Greeting_1
{
strings:
	$a0 = { 2e8aa65d048db60b00b93f042e302446e2fac3 }


condition:
	$a0
}