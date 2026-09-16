rule Win_Trojan_Bypass_1
{
strings:
	$a0 = { 0e57b82f0050bf44001e579a42005b00833e7001007403e99301bf70001e57bf62001e579a }


condition:
	$a0
}