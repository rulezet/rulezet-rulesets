rule Win_Trojan_USSR_14
{
strings:
	$a0 = { 8bf283c60203c12d03000500018904b4 }


condition:
	$a0
}