rule Win_Trojan_Sality_1058
{
strings:
	$a0 = { 8a440500[0-2]3007e9 }


condition:
	$a0
}