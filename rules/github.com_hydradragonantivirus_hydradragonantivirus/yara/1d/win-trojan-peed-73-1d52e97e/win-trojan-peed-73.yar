rule Win_Trojan_Peed_73
{
strings:
	$a0 = { e80f00000039d80f8e01000000c358e96e00000083ecfcbbab??????505050505050 }


condition:
	$a0
}