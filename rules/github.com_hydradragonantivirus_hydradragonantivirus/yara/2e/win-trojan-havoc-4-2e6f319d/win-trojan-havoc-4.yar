rule Win_Trojan_Havoc_4
{
strings:
	$a0 = { 9a3eccba7cd20a0f05a3b5693f0253b7e28af6930a }


condition:
	$a0
}