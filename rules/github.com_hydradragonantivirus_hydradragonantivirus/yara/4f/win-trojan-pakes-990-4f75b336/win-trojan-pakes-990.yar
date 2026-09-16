rule Win_Trojan_Pakes_990
{
strings:
	$a0 = { 60bf0030400057e8????000085c0740261c3fe0757e8????0000fe0f85c074f0e9 }


condition:
	$a0
}