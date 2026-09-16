rule Win_Trojan_Timebomb_3
{
strings:
	$a0 = { e90005c1e902fdad51ad8bc8ad8bd0b280be0400b81003cd13fec680fe1075f483c14032f6 }


condition:
	$a0
}