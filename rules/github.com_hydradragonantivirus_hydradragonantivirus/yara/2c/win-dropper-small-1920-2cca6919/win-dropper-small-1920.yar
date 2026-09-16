rule Win_Dropper_Small_1920
{
strings:
	$a0 = { 83c40c8d85fcfeffff50689430400068cc314000e83602000083c40c68cc314000ff1560204000 }


condition:
	$a0
}