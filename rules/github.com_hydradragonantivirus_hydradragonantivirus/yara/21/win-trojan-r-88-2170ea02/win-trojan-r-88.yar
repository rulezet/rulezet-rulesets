rule Win_Trojan_R_88
{
strings:
	$a0 = { 8d945e00b44eb92000cd217231eb09b44fba8000cd217226b8023dba9e00cd21721c93bf0001 }


condition:
	$a0
}