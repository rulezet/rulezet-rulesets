rule Win_Dropper_Agent_35450
{
strings:
	$a0 = { 6a0068ef18010068f5170100833c2400750b8d54 }

	$a1 = { 53616665204d6f6e20333630 }


condition:
	$a0 and $a1
}