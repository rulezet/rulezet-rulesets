rule Win_Trojan_VB_1702
{
strings:
	$a0 = { 72757373696174650000070000005882 }


condition:
	$a0
}