rule Win_Trojan_Murphy_7
{
strings:
	$a0 = { 8b84e9fa2ea300012e8b84ebfa2ea3 }


condition:
	$a0
}