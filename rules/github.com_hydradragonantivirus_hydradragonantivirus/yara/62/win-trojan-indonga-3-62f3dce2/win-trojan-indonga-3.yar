rule Win_Trojan_Indonga_3
{
strings:
	$a0 = { a2f09ded3ab6fb3fe4ab1e19e2ea5fe65edaec4fe2c4c109 }


condition:
	$a0
}