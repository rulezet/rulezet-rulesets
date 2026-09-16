rule Win_Trojan_DJengine_1
{
strings:
	$a0 = { 02ffff5e81ee03008bfe83e7f08bc7b104d3e88cc903c150b8270050b98d08fcf3a4cb0e1fbed90033ff2e803ed900 }


condition:
	$a0
}