rule Win_Trojan_Trivial_286
{
strings:
	$a0 = { b44eb120ba2901cd21ba9e00b8013dcd218bd88b160001b12eb440 }


condition:
	$a0
}