rule Win_Dropper_Agent_34285
{
strings:
	$a0 = { 4ec5676cf3676674496e43775a73 }


condition:
	$a0
}