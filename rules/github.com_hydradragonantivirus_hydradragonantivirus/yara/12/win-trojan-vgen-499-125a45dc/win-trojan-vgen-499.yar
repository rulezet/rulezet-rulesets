rule Win_Trojan_VGEN_499
{
strings:
	$a0 = { 81ec800052b41a8d5680cd21b44eb927005acd217209e80f007304b44febf38be5b41a5acd21 }


condition:
	$a0
}