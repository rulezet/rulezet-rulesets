rule Win_Trojan_VGEN_354
{
strings:
	$a0 = { 8bd0cd215b83eb038ed833f689dfb90002f3a6745853b452cd210653b430cd215e1f5b3c0272463c0383d612c4 }


condition:
	$a0
}