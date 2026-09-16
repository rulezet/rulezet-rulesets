rule Win_Trojan_V_65
{
strings:
	$a0 = { 2a2e4747c705636f4747b86d008905b8cfb0a318 }


condition:
	$a0
}