rule Win_Trojan_V306_1
{
strings:
	$a0 = { ffc7065aff5649b90500ba57ff8b }


condition:
	$a0
}