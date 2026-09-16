rule Win_Trojan_VGEN_99
{
strings:
	$a0 = { 03008db6b700bf000157a5a4b98000be80008dbec700f3a4b44eb927008d96b100cd217303eb6990a09600241f }


condition:
	$a0
}