rule Win_Trojan_Small_1103
{
strings:
	$a0 = { 686f6f6b646c6c2e646c6c00496e7374616c6c486f6f6b00 }


condition:
	$a0
}