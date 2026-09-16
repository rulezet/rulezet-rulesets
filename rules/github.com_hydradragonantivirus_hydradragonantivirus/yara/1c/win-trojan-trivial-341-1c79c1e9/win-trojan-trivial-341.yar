rule Win_Trojan_Trivial_341
{
strings:
	$a0 = { 01b44eb90100cd217302eb1eb8023dba9e00cd217302eb128bd8e80f00ba8000b44f }


condition:
	$a0
}