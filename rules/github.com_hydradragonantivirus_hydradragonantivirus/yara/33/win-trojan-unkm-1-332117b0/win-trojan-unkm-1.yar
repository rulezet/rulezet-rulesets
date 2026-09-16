rule Win_Trojan_Unkm_1
{
strings:
	$a0 = { 5db8000081ed06018db64802bf000157a5a48d968000b41acd21b44eb906008d964202cd217215e81a007410b4 }


condition:
	$a0
}