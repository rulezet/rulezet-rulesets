rule Win_Trojan_Evil_2
{
strings:
	$a0 = { 9095bf000147033d8bf733c0ba40035233 }


condition:
	$a0
}