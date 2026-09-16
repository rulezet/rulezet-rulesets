rule Win_Trojan_Clicker_45
{
strings:
	$a0 = { 6871741c703a2f47677265176e502e62697afa323930383f2fb0640665702ee468e83feff05b30385d3d5701ffed63 }


condition:
	$a0
}