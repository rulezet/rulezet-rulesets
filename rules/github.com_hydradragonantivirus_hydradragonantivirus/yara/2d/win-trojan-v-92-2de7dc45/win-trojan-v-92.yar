rule Win_Trojan_V_92
{
strings:
	$a0 = { e8022e3004464c75f98be1fbc3601474029cff1edd02c309a2 }


condition:
	$a0
}