rule Win_Trojan_KKA_1
{
strings:
	$a0 = { 01888632028d7cff8db63202a48bf7e2e3c3eb18e8ceffb440b94a018d960001cd21fe8623 }


condition:
	$a0
}