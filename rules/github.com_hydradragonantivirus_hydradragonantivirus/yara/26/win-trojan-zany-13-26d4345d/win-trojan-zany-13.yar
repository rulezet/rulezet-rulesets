rule Win_Trojan_Zany_13
{
strings:
	$a0 = { e800005d81ed0300ffb69100ffb69300b41a8d969f00cd21b44eb903008d969900cd217262b8023d8d96bd00cd21 }


condition:
	$a0
}