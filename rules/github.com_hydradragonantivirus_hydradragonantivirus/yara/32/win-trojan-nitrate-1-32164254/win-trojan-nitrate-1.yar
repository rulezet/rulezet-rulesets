rule Win_Trojan_Nitrate_1
{
strings:
	$a0 = { e800005d81ed05008db61f00b946032e8a042e328666032e880446e2f2 }


condition:
	$a0
}