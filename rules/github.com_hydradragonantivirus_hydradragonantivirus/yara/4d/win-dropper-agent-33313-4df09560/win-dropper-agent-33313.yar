rule Win_Dropper_Agent_33313
{
strings:
	$a0 = { 64ff30648920c645f7006a006a006a036a006a0168000000808b45f8e8??f3ffff50e8d9f6ffff8bd883fbff750b }


condition:
	$a0
}