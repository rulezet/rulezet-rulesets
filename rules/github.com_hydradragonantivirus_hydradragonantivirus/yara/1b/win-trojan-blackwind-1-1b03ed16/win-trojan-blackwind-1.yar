rule Win_Trojan_BlackWind_1
{
strings:
	$a0 = { e2fa5b59585ec3e8dcff8984e4028d940501b440 }


condition:
	$a0
}