rule Win_Trojan_Dialer_644
{
strings:
	$a0 = { 3539014332352d434242442d346463632d384339382d4441 }

	$a1 = { 3f6b313769643d307825782606 }


condition:
	$a0 and $a1
}