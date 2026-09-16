rule Win_Trojan_Naughty_2
{
strings:
	$a0 = { 0eb202cd21b41aba0901cd21b44eb90600ba0301cd217231e80b00b44fcd217228e80200ebf5b4 }


condition:
	$a0
}