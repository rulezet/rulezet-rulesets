rule Win_Dropper_Small_5114
{
strings:
	$a0 = { e82961000068e0a140008d8530fdffff50e8186100006a008d8530fdffff50e8f2600000 }


condition:
	$a0
}