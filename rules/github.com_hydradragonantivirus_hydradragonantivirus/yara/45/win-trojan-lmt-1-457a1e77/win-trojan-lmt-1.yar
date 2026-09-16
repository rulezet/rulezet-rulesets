rule Win_Trojan_LMT_1
{
strings:
	$a0 = { 544d4c0000000000000000e0008e810b010219000200000006 }


condition:
	$a0
}