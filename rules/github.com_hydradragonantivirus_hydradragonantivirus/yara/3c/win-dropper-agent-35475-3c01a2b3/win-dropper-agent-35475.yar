rule Win_Dropper_Agent_35475
{
strings:
	$a0 = { 60be006003008dbe00b0fdff5789e58d9c2480c1 }


condition:
	$a0
}