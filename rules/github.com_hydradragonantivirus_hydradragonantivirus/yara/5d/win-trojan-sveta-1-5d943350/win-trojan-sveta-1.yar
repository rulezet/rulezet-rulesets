rule Win_Trojan_Sveta_1
{
strings:
	$a0 = { 1e06b800908ec08d3600018d3e0001b93501fcf3a406b83b0150cbe85e002bc9ba0301b44ecd21eb0590b44fcd21723a }


condition:
	$a0
}