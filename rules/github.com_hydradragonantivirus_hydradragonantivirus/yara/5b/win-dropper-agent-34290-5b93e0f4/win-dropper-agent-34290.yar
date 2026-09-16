rule Win_Dropper_Agent_34290
{
strings:
	$a0 = { 4ec5116cf3226674336e43775a73 }


condition:
	$a0
}