rule Win_Trojan_Agip_1
{
strings:
	$a0 = { e9cc0390909090909c5031c02e3826da }


condition:
	$a0
}