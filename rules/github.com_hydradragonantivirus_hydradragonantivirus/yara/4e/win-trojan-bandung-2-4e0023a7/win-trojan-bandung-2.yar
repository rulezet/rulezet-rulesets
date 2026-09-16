rule Win_Trojan_Bandung_2
{
strings:
	$a0 = { 0500558e0200000001005903000049010000050000006a08 }


condition:
	$a0
}