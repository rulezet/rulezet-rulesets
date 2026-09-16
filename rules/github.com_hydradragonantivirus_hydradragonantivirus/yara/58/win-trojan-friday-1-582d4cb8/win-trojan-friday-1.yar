rule Win_Trojan_Friday_1
{
strings:
	$a0 = { bfb701b90c00fcf3a6077503e991 }


condition:
	$a0
}