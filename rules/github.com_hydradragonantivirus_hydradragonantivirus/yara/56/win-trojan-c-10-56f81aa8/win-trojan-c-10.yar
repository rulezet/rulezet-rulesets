rule Win_Trojan_C_10
{
strings:
	$a0 = { 53b4408b8e040481c158028bd581c20005cd21 }


condition:
	$a0
}