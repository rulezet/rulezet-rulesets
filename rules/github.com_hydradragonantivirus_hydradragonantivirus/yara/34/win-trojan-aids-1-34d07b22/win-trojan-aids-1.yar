rule Win_Trojan_AIDS_1
{
strings:
	$a0 = { ae426e4c72034600000400a01000 }


condition:
	$a0
}