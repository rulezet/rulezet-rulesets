rule Win_Trojan_Renos_6
{
strings:
	$a0 = { e8b800000038badf090000e200ed1b000000000000bf00e424007e7d4b00000092a6 }


condition:
	$a0
}