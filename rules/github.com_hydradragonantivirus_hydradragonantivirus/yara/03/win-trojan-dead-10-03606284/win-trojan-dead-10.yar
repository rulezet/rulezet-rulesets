rule Win_Trojan_Dead_10
{
strings:
	$a0 = { b9ac01[9-11]8d7c14[2-3]2e300547e2f8 }


condition:
	$a0
}