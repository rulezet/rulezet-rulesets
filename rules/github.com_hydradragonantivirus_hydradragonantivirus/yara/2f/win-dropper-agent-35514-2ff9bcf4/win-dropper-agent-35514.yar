rule Win_Dropper_Agent_35514
{
strings:
	$a0 = { 558becb8bf049dd8bbbf92b9c150e800000000582d }


condition:
	$a0
}