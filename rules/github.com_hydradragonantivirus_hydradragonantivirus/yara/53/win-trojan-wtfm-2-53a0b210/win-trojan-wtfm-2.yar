rule Win_Trojan_Wtfm_2
{
strings:
	$a0 = { 5fb4ec80c48632254757ebf12bf681ce9a00b9f7ff81e9defe390c722f2500003562ea3904 }


condition:
	$a0
}