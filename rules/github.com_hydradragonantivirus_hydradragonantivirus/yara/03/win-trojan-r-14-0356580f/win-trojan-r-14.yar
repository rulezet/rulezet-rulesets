rule Win_Trojan_R_14
{
strings:
	$a0 = { b4408d960001cd21b8004233c999cd21b91a00b4408d961703cd21b43ecd21b44feba1 }


condition:
	$a0
}