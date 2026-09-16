rule Win_Trojan_Kalah_1
{
strings:
	$a0 = { cd218b0e00002e3b0e0001750b8b0e02002e3b0e0201 }


condition:
	$a0
}