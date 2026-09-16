rule Win_Trojan_Jovial_1
{
strings:
	$a0 = { bf00018db6ef0290a5a5a433c08ed8a10c0089866b03a10e0089866d03a18400a30c00a18600a30e000e1fb41a }


condition:
	$a0
}