rule Win_Trojan_Small_199
{
strings:
	$a0 = { ab687af7ba2b1bbcc6fe1b17a6acfcae581f14e144c074c6a57418a64309043b384305912245 }


condition:
	$a0
}