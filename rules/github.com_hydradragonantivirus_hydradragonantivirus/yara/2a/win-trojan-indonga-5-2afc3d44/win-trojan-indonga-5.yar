rule Win_Trojan_Indonga_5
{
strings:
	$a0 = { ce1cc91966e2276b10d74a450e168b128a06187b0ef0ed35 }


condition:
	$a0
}