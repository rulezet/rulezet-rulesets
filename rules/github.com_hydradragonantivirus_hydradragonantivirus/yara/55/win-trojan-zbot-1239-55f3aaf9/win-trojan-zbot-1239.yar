rule Win_Trojan_Zbot_1239
{
strings:
	$a0 = { ff156849410083f800751e83ec0489042489e05068f80000005050ff15dc4641 }


condition:
	$a0
}