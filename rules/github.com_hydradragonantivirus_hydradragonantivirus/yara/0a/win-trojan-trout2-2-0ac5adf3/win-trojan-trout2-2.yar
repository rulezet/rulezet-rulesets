rule Win_Trojan_Trout2_2
{
strings:
	$a0 = { 31c001dd9031c200d0a6d40a8d13f580f540e0fe3f00e0d3c0262a26207413e881e52080d3c0f7d601c388fe565b }


condition:
	$a0
}