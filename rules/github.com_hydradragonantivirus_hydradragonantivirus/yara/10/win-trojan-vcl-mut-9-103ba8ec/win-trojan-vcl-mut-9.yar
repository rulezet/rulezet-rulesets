rule Win_Trojan_VCL_MUT_9
{
strings:
	$a0 = { cd21538bec81ec800052b41a8d56809393cd21b44eb927005acd217209e814007304b44feb }


condition:
	$a0
}