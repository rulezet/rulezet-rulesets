rule Win_Trojan_Anti_22
{
strings:
	$a0 = { a1130448a31304b106d3e08ec0b90002 }


condition:
	$a0
}