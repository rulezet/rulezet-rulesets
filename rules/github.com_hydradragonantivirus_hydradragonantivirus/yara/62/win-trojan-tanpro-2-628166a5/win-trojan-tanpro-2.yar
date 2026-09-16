rule Win_Trojan_Tanpro_2
{
strings:
	$a0 = { 402e8b1e22012e8b0e2401baed03cd21b43e2e8b1e2201 }


condition:
	$a0
}