rule Win_Trojan_Agent_34202
{
strings:
	$a0 = { e80e000000e99efdffff558bec81ec2803000050b8efcdab00505883c404e80000000083c4086873d17712c3 }


condition:
	$a0
}