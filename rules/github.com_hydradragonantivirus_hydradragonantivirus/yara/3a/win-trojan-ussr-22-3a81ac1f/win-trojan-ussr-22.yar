rule Win_Trojan_USSR_22
{
strings:
	$a0 = { be1001b932008a2480f4dd882446e2f6 }


condition:
	$a0
}