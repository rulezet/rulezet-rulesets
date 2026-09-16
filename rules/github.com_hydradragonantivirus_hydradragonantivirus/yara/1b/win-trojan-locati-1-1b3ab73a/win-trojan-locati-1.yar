rule Win_Trojan_Locati_1
{
strings:
	$a0 = { 8b9424641500006a0068000000046a006a006a008d4c243452 }


condition:
	$a0
}