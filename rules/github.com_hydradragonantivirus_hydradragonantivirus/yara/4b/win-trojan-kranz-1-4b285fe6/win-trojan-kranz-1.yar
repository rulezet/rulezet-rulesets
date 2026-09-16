rule Win_Trojan_Kranz_1
{
strings:
	$a0 = { be030133c933c0ac3c1a740403c8ebf7 }


condition:
	$a0
}