rule Win_Trojan_Deviator_1
{
strings:
	$a0 = { 01010055df000000000100dc08000045010000030000002503 }


condition:
	$a0
}