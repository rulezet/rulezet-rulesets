rule Win_Dropper_Agent_35653
{
strings:
	$a0 = { 558bec538b5d08568b750c578b7d1085f67509833d }

	$a1 = { 17cfc22c1b2b3748456b7070 }

	$a2 = { 76572409540d2555 }


condition:
	$a0 and $a1 and $a2
}