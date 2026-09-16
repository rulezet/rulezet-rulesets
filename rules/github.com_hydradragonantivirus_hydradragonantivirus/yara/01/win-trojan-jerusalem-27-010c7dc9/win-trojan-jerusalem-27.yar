rule Win_Trojan_Jerusalem_27
{
strings:
	$a0 = { 2eff1e20013dffac7514b862ec2e8b0e0701bf00 }


condition:
	$a0
}