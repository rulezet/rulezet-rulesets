rule Win_Trojan_VLAD_21
{
strings:
	$a0 = { 8104b000d0c8f6d82e300402c046e2f4c3 }


condition:
	$a0
}