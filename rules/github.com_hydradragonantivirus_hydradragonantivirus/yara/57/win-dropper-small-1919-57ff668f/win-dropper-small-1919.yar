rule Win_Dropper_Small_1919
{
strings:
	$a0 = { 8bd88bcbbad83c4000b80a000000e8d4faffff84c074078bc3e819fcffff }


condition:
	$a0
}