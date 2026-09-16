rule Win_Trojan_Manola_1
{
strings:
	$a0 = { b44acd2172e7bb3c00b448cd2172de }


condition:
	$a0
}