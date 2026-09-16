rule Win_Trojan_Krile_7
{
strings:
	$a0 = { d6be2d4d5c977a4894079e780af807ac3bb88cd3153375813ee80f009ae8f9ff9a9ceb019a }


condition:
	$a0
}