rule Win_Trojan_Construct_1
{
strings:
	$a0 = { 4d1366137013761380138a138f139c13b413cd13d713dd13e713f113f61303141b1434143e14 }


condition:
	$a0
}