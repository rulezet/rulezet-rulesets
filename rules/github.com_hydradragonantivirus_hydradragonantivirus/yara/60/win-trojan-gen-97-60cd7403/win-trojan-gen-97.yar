rule Win_Trojan_Gen_97
{
strings:
	$a0 = { 8bd781c21300b8023dcd217303e994 }


condition:
	$a0
}