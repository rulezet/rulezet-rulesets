rule Win_Trojan_ByteSV_3
{
strings:
	$a0 = { e800005d83ed070e1f8d864100508a4621b9c4028d7641300446e2fbc3 }


condition:
	$a0
}