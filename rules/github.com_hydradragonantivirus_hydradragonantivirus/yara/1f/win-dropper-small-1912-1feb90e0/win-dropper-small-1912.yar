rule Win_Dropper_Small_1912
{
strings:
	$a0 = { 6a006a006a026a006a03680000004055e8f1f8ffff8bd883fbff741d }


condition:
	$a0
}