rule Win_Trojan_Horns_1
{
strings:
	$a0 = { a044750298cf80fc3d756aa80375722e833e2d02ff756a }


condition:
	$a0
}