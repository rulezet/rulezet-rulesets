rule Win_Trojan_Trivial_567
{
strings:
	$a0 = { e800005db824258d??????0021b823258d[0-3]cd21b44eb9 }


condition:
	$a0
}