rule Win_Trojan_DIW_7
{
strings:
	$a0 = { 8bc2051b0050c32e9c589eb4097303e98600fab0ade664eb00fb5abf00018bf283c609b90300f3a452b42fcd218b }


condition:
	$a0
}