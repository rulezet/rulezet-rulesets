rule Win_Trojan_Howard_1
{
strings:
	$a0 = { 52b8fe05babaa6f7d0f7d2cd16b8fd05babaa6bb0000f7d0f7d2cd165a5d5fe90000e800005d81ed27018db64304 }


condition:
	$a0
}