rule Win_Trojan_Metall_1
{
strings:
	$a0 = { 01010503008be8e9a201b840008ec026a06c003c2872493c327345b40fcd10bad007bb00b03c07740dbb00b83c03 }


condition:
	$a0
}