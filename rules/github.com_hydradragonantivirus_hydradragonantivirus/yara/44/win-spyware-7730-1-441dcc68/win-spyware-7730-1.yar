rule Win_Spyware_7730_1
{
strings:
	$a0 = { e80e000000e99efdffff558bec81ec2803000050b8efcdab00505883c404e80000000083c4086867f87212c3 }


condition:
	$a0
}