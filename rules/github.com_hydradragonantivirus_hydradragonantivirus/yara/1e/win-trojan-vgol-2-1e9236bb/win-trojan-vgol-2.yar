rule Win_Trojan_VGOL_2
{
strings:
	$a0 = { d2b440e8edfa3df8067526803ef8064d740ab907 }


condition:
	$a0
}