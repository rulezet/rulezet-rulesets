rule Win_Trojan_VGEN_295
{
strings:
	$a0 = { ed06008db6ac00bf000157a5a4b98000be80008dbebd00f3a4b44eb923008d96af00cd21730d8db6bd00bf8000b9 }


condition:
	$a0
}