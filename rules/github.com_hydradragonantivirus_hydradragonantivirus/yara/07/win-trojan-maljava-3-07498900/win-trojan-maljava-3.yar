rule Win_Trojan_Maljava_3
{
strings:
	$a0 = { 612f48656c702e636c617373504b }

	$a1 = { 612f61706c2e636c617373504b }


condition:
	$a0 and $a1
}