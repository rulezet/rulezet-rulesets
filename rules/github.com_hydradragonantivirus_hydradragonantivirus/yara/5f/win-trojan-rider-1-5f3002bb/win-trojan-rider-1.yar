rule Win_Trojan_Rider_1
{
strings:
	$a0 = { 496728b3c3288828a0003bff7c008de56f74023f353601a9006219c11972fbf888de8d0000ca39ca72043dcf7e0cabac }


condition:
	$a0
}