rule Win_Trojan_B_3
{
strings:
	$a0 = { 8087507d224b75f8a14c0026a38401a14e0026a386 }


condition:
	$a0
}