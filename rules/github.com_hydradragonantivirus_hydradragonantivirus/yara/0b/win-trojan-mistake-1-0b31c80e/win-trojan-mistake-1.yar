rule Win_Trojan_Mistake_1
{
strings:
	$a0 = { 32e4cd1a80fe03760a909090909052e8 }


condition:
	$a0
}