rule Win_Trojan_DIW_2
{
strings:
	$a0 = { e8000087f75e83ee065681c61a01a5a5b41a5a528bfa81c21e01cd218bd781c21401fcb44eb92000cd21720bb4 }


condition:
	$a0
}