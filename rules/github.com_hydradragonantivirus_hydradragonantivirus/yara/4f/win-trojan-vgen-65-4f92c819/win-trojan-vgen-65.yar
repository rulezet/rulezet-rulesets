rule Win_Trojan_VGEN_65
{
strings:
	$a0 = { b44eb90700ba9a02cd217303e9e700061fba9e00b8023dcd2172f10e1f8bd8b43fb90200baaf02cd21813eaf023b }


condition:
	$a0
}