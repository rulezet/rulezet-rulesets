rule Win_Trojan_Gen_34
{
strings:
	$a0 = { bf000147033d8bf733c0ba54025233 }


condition:
	$a0
}