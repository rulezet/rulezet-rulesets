rule Win_Dropper_Agent_35454
{
strings:
	$a0 = { 807c2408010f85c201000060be005000108dbe00c0ffff57 }


condition:
	$a0
}