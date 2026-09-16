rule Win_Trojan_Peed_343
{
strings:
	$a0 = { 2d10ff00004beb6551eb10b8ffffffff8d40f883c00529c249eb61b9c2010000 }


condition:
	$a0
}