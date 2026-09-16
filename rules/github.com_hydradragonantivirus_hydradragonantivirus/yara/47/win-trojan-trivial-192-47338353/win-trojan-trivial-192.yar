rule Win_Trojan_Trivial_192
{
strings:
	$a0 = { 1aba2401cd21b44eb21ecd21b8123db242cd2193b440b12487d6cd21c32a2e434f4d }


condition:
	$a0
}