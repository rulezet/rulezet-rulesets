rule Win_Dropper_Small_1906
{
strings:
	$a0 = { 6a056a006a008d85f8fdffff506a006a00e854000000 }


condition:
	$a0
}