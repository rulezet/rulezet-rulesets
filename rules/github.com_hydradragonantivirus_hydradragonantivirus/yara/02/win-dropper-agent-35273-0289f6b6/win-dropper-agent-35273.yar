rule Win_Dropper_Agent_35273
{
strings:
	$a0 = { 4ec5676cf3676674496e43775a730000962b01005d }


condition:
	$a0
}