rule Win_Trojan_Pox_1
{
strings:
	$a0 = { 0190e800005d81ed0601501e06b8cdabcd13eb0490e9b30081fbcdab7502ebf5 }


condition:
	$a0
}