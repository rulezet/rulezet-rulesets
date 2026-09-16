rule Win_Trojan_VCM_1
{
strings:
	$a0 = { 03012e8b9ee7022e899eea022e8abee9022e88beec022ec686b302002ec686e60200b41a8d96b802cd21b44eb9 }


condition:
	$a0
}