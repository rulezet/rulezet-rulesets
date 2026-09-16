rule Win_Trojan_Monster_56
{
strings:
	$a0 = { b93502be????fc300446e2fbeb24 }


condition:
	$a0
}