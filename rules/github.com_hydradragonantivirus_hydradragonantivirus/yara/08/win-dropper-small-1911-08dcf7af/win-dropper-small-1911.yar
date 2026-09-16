rule Win_Dropper_Small_1911
{
strings:
	$a0 = { 74205768000000046a03576a018d85dcfeffff680000018050ff152c104000 }


condition:
	$a0
}