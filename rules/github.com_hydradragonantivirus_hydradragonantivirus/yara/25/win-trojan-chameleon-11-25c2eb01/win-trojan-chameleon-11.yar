rule Win_Trojan_Chameleon_11
{
strings:
	$a0 = { b961fcf8fb90313cf9f84f90fbf5fc46e2f1 }


condition:
	$a0
}