rule Win_Trojan_Kitana_2
{
strings:
	$a0 = { d2741d48cd13050101ba80008ac88bd8cd13803f8574084041cd1387f3e2fac387de2eff0e1304 }


condition:
	$a0
}