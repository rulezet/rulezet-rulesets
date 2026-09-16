rule Win_Trojan_CZ_1
{
strings:
	$a0 = { b8023d1ec55604e8bbfb1f7234a33a00 }


condition:
	$a0
}