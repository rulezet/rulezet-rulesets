rule Win_Trojan_Tiny_43
{
strings:
	$a0 = { 3dcd32723493e83c00b43f8bfa0e1f }


condition:
	$a0
}