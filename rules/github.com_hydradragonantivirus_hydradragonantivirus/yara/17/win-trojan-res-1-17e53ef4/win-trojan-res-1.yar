rule Win_Trojan_Res_1
{
strings:
	$a0 = { bc007c8ed38edbfb68007c0781c300010653b8060232f6b90800cd1372f4cb }


condition:
	$a0
}