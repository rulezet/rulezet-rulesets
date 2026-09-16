rule Win_Trojan_Lyceum_2
{
strings:
	$a0 = { aaca020080fcbb74f62e803e3208ff7503e921013d0242 }


condition:
	$a0
}