rule Win_Trojan_Peed_186
{
strings:
	$a0 = { e85e0000007601b8bffe1e2cf3ffb439ba1d010d6a036a026a016a00e8520000 }


condition:
	$a0
}