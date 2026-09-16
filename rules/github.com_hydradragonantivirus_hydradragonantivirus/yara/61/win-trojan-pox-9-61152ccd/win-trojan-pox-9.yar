rule Win_Trojan_Pox_9
{
strings:
	$a0 = { 01010055df00000000ffff000000002f010000050000000103 }


condition:
	$a0
}