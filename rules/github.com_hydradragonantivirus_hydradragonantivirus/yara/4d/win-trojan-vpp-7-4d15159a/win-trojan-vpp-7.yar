rule Win_Trojan_Vpp_7
{
strings:
	$a0 = { e76d3887b365bbe52e8eb3f12ecc3e2b19a0f5b60610a6fd3aa3b41950a33ef0062c9e743a97b43ded }


condition:
	$a0
}