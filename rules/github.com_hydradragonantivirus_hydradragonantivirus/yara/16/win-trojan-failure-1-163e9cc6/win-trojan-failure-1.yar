rule Win_Trojan_Failure_1
{
strings:
	$a0 = { b435cd21891c8c4402b425cd210e07c3 }


condition:
	$a0
}