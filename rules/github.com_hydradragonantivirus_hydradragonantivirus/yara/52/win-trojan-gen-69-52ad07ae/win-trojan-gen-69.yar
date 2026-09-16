rule Win_Trojan_Gen_69
{
strings:
	$a0 = { 018904b4408bd781c20301b9b009cd21 }


condition:
	$a0
}