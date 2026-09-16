rule Win_Trojan_Tiny_29
{
strings:
	$a0 = { f3a4b44eb15987d1fec6cd217301cbb8023d99b29ecd2193b43fb25ffec65459cd21a31701 }


condition:
	$a0
}