rule Win_Dropper_Agent_34363
{
strings:
	$a0 = { 68db144000e8d7ffffffe88afbffffe893fdffffe84ffeffff50e84dffffffc3 }


condition:
	$a0
}