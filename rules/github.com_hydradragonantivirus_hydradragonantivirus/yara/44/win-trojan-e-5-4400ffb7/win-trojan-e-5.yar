rule Win_Trojan_E_5
{
strings:
	$a0 = { 0e0e1f07bf2300e80300eb16f28a260d00be2300b9dd00ac32c4aae2fac3 }


condition:
	$a0
}