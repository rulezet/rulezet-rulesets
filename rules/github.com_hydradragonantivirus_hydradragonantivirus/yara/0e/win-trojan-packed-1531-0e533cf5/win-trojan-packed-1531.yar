rule Win_Trojan_Packed_1531
{
strings:
	$a0 = { e078727479[0-50]e02e61646174610000 }


condition:
	$a0
}