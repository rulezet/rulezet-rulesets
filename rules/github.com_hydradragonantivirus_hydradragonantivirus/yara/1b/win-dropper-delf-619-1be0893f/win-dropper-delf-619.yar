rule Win_Dropper_Delf_619
{
strings:
	$a0 = { 6a006880000000516a0052508d434850e890e2ffff }


condition:
	$a0
}