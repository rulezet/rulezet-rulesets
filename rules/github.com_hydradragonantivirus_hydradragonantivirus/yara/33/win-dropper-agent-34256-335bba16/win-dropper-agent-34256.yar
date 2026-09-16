rule Win_Dropper_Agent_34256
{
strings:
	$a0 = { 2bdb33c0b40196682d204000536803001f00e8ba050000 }


condition:
	$a0
}