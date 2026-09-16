rule Win_Trojan_Gen_139
{
strings:
	$a0 = { a31304b106d3e08ec0a3667c31c0cd1331dbb908 }


condition:
	$a0
}