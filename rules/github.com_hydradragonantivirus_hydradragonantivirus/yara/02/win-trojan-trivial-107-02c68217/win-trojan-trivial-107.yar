rule Win_Trojan_Trivial_107
{
strings:
	$a0 = { 2a2e2a00b44eb601cd21b8013dba9e00cd219387d1b440 }


condition:
	$a0
}