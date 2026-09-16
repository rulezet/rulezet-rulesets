rule Win_Trojan_Lauren_4
{
strings:
	$a0 = { ed0a01bf00018db67c03fca5a5a5a4b8ffff5058fa83ec }


condition:
	$a0
}