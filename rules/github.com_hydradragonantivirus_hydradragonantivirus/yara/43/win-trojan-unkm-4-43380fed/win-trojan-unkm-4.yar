rule Win_Trojan_Unkm_4
{
strings:
	$a0 = { 968000b41acd21b44eb906008d967202cd217215e81a007410b43ecd21b8004fcd217205e80a00 }


condition:
	$a0
}