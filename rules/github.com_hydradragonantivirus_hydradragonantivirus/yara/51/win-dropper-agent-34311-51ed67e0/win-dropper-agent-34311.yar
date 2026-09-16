rule Win_Dropper_Agent_34311
{
strings:
	$a0 = { 4ec5116cf3226674336e43775573 }


condition:
	$a0
}