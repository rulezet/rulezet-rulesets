rule Win_Trojan_Agent_34242
{
strings:
	$a0 = { e80e000000e99efdffff558bec81ec2803000050b8efcdab00505883c404e80000000083c4086828c37812c3 }


condition:
	$a0
}