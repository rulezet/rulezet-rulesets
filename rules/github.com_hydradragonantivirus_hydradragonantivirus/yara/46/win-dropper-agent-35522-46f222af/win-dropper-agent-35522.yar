rule Win_Dropper_Agent_35522
{
strings:
	$a0 = { 558becb87356ce76bb7d4a4a2250e800000000582d }


condition:
	$a0
}