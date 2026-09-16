rule Win_Dropper_Agent_35409
{
strings:
	$a0 = { 6675636b75 }

	$a1 = { 6f676f6e5c4e6f746966795c }

	$a2 = { 397d73686f70656e59882a342a40 }

	$a3 = { 0675736572c7 }


condition:
	$a0 and $a1 and $a2 and $a3
}