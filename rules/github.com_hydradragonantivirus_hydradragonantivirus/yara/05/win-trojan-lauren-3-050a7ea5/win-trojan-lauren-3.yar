rule Win_Trojan_Lauren_3
{
strings:
	$a0 = { 0a01bf00018db67b03fca5a5a5a4b8ffff5058fa83ec }


condition:
	$a0
}