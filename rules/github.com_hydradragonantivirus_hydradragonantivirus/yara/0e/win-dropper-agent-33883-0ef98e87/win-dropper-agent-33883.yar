rule Win_Dropper_Agent_33883
{
strings:
	$a0 = { 4d5a80000100000004001000ff }

	$a1 = { 4d5a7502eb0ab800000000e9??0500008b45 }


condition:
	$a0 and $a1
}