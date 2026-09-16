rule Win_Trojan_BadSector_1
{
strings:
	$a0 = { d8be8400bf0e00a5a5fac744fc2a008c44fefbbe2000bf }


condition:
	$a0
}