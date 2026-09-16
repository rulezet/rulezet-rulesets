rule Win_Trojan_Mis_2
{
strings:
	$a0 = { 32e4cd138026fa7d808b1ef77d0e582d }


condition:
	$a0
}