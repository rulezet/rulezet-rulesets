rule Win_Trojan_Changeup_4
{
strings:
	$a0 = { 433030302d706c6175646174696f6e }


condition:
	$a0
}