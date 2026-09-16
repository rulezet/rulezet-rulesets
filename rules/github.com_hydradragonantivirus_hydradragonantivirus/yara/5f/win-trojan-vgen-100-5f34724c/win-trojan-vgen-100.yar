rule Win_Trojan_VGEN_100
{
strings:
	$a0 = { ed03008db6cc00bf000157a5a4b98000be80008dbedd00f3a4b44eb927008d96c600cd217303eb7c90a09600241f }


condition:
	$a0
}