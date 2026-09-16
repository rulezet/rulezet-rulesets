rule Win_Trojan_Peed_144
{
strings:
	$a0 = { 69c0cc5a0000e98300000089daf7da01d0ba6fffffff83f8007462c368bbb8ffff56e85b00000035 }


condition:
	$a0
}