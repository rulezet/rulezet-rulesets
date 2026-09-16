rule Win_Trojan_Peed_74
{
strings:
	$a0 = { e80f00000039d80f8e01000000c358e96e00000083ecfcbbab604000505050505050 }


condition:
	$a0
}