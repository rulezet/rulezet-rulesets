rule Win_Trojan_ARCV_24
{
strings:
	$a0 = { 408b9c3004b9e1028d940e01cd21e8d6ffe8c3ffc3496d }


condition:
	$a0
}