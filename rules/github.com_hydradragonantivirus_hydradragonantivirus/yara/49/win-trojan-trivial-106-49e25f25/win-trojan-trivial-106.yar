rule Win_Trojan_Trivial_106
{
strings:
	$a0 = { 2a2e2a00b44eb601cd21b8013dba9e00cd2187d193b440 }


condition:
	$a0
}