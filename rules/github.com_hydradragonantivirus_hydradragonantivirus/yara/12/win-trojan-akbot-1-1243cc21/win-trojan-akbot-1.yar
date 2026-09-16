rule Win_Trojan_Akbot_1
{
strings:
	$a0 = { 6a008d8d94e6ffff51e8ae7d000083c404508d9594e6ffff528b8548e5ffff50ff1504c2001068e8c7021068900d0110e83a370000 }


condition:
	$a0
}