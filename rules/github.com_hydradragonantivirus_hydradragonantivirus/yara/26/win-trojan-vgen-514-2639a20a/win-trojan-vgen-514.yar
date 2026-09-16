rule Win_Trojan_VGEN_514
{
strings:
	$a0 = { c401bf000157a5a4c686ba0201b41a8d968f02cd218d965902b44eb90700cd21726233c9e8fe00 }


condition:
	$a0
}