rule Win_Trojan_Marzia_1
{
strings:
	$a0 = { d0bc007cbe007cbf007efb0e0e1f07fcb90001f3a5be297effe6cd1250b106d3e02dc0008e }


condition:
	$a0
}