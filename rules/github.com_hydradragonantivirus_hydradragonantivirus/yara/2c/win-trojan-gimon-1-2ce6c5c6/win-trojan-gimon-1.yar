rule Win_Trojan_Gimon_1
{
strings:
	$a0 = { 3d0844753eb45b33c98d96a4083ec6863d084ecd2193b440b9d0088d960000cd21b43ecd21 }


condition:
	$a0
}