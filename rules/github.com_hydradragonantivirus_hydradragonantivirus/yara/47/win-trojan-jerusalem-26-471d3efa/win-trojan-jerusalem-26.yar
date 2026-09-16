rule Win_Trojan_Jerusalem_26
{
strings:
	$a0 = { 9c2eff1e20013dffac7514b861ec2e8b0e0701bf00 }


condition:
	$a0
}