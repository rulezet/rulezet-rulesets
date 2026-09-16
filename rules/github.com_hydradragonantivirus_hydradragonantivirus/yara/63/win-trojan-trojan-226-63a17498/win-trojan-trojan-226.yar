rule Win_Trojan_Trojan_226
{
strings:
	$a0 = { 86e30211b41a8d96b802cd218d966102b44eb90700cd21 }


condition:
	$a0
}