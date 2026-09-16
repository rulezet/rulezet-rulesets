rule Win_Trojan_Zbot_1229
{
strings:
	$a0 = { 31c0e801000000c389ff89e583ec148d5dec6a00ff15041040006a00ff150410400031db88 }


condition:
	$a0
}