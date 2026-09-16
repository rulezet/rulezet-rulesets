rule Win_Trojan_Malaga_1
{
strings:
	$a0 = { 0400a31304b106d3e02dc0078ec08bf48bfeb900012ea3 }


condition:
	$a0
}