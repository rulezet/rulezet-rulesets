rule Win_Trojan_Silvina_1
{
strings:
	$a0 = { 010100558e01000000ffff180300002003000002000000a01e }


condition:
	$a0
}