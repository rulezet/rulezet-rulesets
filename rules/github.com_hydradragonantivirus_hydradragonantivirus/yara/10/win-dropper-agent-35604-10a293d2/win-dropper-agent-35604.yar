rule Win_Dropper_Agent_35604
{
strings:
	$a0 = { 81e9d51a99d6535fe8a40000000000080000eb00007b76 }

	$a1 = { 55262c503d48393d25 }

	$a2 = { 3d5570250bec }


condition:
	$a0 and $a1 and $a2
}