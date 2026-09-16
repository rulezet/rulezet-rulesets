rule Win_Trojan_New_2
{
strings:
	$a0 = { eb5d052ec6475cfffc2e807f5b007417be0a0003f3bf00 }


condition:
	$a0
}