rule Win_Dropper_Pecodrop_1
{
strings:
	$a0 = { 744f6a0068800000006a026a006a0268000000408d85e4feffff50e8307500008bd883fbff742a }


condition:
	$a0
}