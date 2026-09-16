rule Win_Trojan_Jerusalem_30
{
strings:
	$a0 = { 2eff1e18013dffac7514b870ec2e8b0e0701bf00 }


condition:
	$a0
}