rule Win_Trojan_Dikshev_16
{
strings:
	$a0 = { 652ab44eb99e0087ce99fec6cd217301c3b22987d6afb02ef2aea5a4b45bcd21720393b440eb }


condition:
	$a0
}