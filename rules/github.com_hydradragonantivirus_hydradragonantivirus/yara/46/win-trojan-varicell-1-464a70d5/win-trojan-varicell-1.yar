rule Win_Trojan_Varicell_1
{
strings:
	$a0 = { b8cdabcd13eb0490e9b10081fbcdab7502ebf55351 }


condition:
	$a0
}