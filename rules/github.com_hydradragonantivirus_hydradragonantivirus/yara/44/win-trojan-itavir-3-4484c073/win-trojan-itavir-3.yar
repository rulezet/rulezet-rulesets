rule Win_Trojan_ItaVir_3
{
strings:
	$a0 = { 83c4025a595b5850535152cd26720d83 }


condition:
	$a0
}