rule Win_Dropper_Agent_35444
{
strings:
	$a0 = { 558bec83c4f0b8a0516001e854e6ffff33c055689b52600164ff306489 }


condition:
	$a0
}