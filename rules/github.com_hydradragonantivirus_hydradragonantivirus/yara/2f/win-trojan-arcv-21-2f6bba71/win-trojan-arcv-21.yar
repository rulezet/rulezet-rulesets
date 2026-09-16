rule Win_Trojan_ARCV_21
{
strings:
	$a0 = { ba6cfebf1100e2fe472e81050000474275f6 }


condition:
	$a0
}