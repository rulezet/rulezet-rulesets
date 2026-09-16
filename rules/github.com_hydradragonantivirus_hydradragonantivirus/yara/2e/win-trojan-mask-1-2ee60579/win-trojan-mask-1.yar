rule Win_Trojan_Mask_1
{
strings:
	$a0 = { e800005d8d76fdb94109b07f3046114504d4e2f8 }


condition:
	$a0
}