rule Win_Trojan_Parite_6
{
strings:
	$a0 = { d270effbdac4845b127ef3543d39746007d63d2d510280256f1459c213cbc65c56 }


condition:
	$a0
}