rule Win_Trojan_Seat_3
{
strings:
	$a0 = { 01bb610987cb2e808468ffa946e2f775654f0f52362478c96342a0ca605757bb5757575757b2af921acb6ae52f75 }


condition:
	$a0
}