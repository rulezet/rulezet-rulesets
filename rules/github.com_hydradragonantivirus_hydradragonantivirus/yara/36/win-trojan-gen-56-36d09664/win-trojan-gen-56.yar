rule Win_Trojan_Gen_56
{
strings:
	$a0 = { 19cd218ad080fa02720380c27eb80903bb9b07b90100b600cd13b940008ac1e670b0ffe671e2f6 }


condition:
	$a0
}