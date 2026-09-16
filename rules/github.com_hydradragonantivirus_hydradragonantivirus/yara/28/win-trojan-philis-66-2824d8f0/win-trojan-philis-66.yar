rule Win_Trojan_Philis_66
{
strings:
	$a0 = { c8000000b800dd4000048750c390900f8414cbffff6a00e94ac7ffff00000064ff30648920b8e4dd4000e954ffffff00006a006a00e8cf64ffffe92bc3ffff00008d85c1fdffff50 }


condition:
	$a0
}