rule Win_Trojan_Krile_6
{
strings:
	$a0 = { 39b8dc4f2b3af51836ea65fc1e6c9a65c255b88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}