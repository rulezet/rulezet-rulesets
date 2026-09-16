rule Win_Trojan_VGEN_294
{
strings:
	$a0 = { 81ed06008db6aa00bf000157a5a4b98000be80008dbebb00f3a4b44eb923008d96ad00cd21730d8db6bb00bf8000b9 }


condition:
	$a0
}