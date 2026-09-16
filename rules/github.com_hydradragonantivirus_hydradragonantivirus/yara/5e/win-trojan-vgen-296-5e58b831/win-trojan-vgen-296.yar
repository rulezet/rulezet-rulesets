rule Win_Trojan_VGEN_296
{
strings:
	$a0 = { ed06008db6c100bf000157a5a4b98000be80008dbed200f3a4b44eb923008d96c400cd21730d8db6d200bf8000b9 }


condition:
	$a0
}