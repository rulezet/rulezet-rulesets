rule Win_Dropper_Agent_34410
{
strings:
	$a0 = { 8d1d3a104000e82201000003d8ffd3e8a6000000e8d7010000c3e821010000c3 }


condition:
	$a0
}