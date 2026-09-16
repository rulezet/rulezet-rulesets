rule Win_Dropper_Agent_36267
{
strings:
	$a0 = { 558becb9060000006a006a004975f9535657b868a04000e8fca8ffff33c05568 }


condition:
	$a0
}