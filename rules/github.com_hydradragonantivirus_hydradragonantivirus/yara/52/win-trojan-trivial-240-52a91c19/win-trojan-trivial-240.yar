rule Win_Trojan_Trivial_240
{
strings:
	$a0 = { b43ecd21b44febe12a2e636f6d00 }


condition:
	$a0
}