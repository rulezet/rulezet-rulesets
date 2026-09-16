rule Win_Trojan_Amstrad_3
{
strings:
	$a0 = { 7257ba1202b8023dcd21a314018bd8 }


condition:
	$a0
}