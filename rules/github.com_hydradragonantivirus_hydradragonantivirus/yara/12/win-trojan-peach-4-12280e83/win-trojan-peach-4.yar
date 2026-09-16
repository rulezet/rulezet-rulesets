rule Win_Trojan_Peach_4
{
strings:
	$a0 = { eb00be11018ccb8b0403c350b8df0150cb6702 }


condition:
	$a0
}