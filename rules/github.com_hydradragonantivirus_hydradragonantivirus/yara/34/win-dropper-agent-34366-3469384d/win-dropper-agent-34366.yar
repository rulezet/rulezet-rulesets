rule Win_Dropper_Agent_34366
{
strings:
	$a0 = { 558bec68e0144000e89efdffff90e8fffbffff33f6e823ffffffe8d5ffffff }


condition:
	$a0
}