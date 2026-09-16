rule Win_Dropper_Small_5130
{
strings:
	$a0 = { e84ce6ffffe867e0ffff6a006a006a00a114560010e853eeffff506a006a00e841f3ffff }


condition:
	$a0
}