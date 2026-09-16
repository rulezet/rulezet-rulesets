rule Win_Trojan_Silly_47
{
strings:
	$a0 = { 160301bbda00263b17742133c933d22e8b1e0a01b800 }


condition:
	$a0
}