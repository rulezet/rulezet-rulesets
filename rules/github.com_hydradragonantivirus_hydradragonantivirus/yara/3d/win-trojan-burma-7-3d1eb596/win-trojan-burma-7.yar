rule Win_Trojan_Burma_7
{
strings:
	$a0 = { 6901e8ff00e86301e8f900e86901e81f01e8e000e8 }


condition:
	$a0
}