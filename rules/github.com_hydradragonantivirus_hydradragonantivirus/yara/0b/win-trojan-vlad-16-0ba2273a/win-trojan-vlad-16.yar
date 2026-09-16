rule Win_Trojan_VLAD_16
{
strings:
	$a0 = { 5d81ed0301eb09902a2e633f6d00d007b41abae0facd218d960c01b44eb90700cd21720ceb2090e81700b44fcd2173 }


condition:
	$a0
}