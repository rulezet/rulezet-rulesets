rule Win_Trojan__0502_0001_000_1
{
strings:
	$a0 = { 02f3a4e90001e83400b440ba0001b97800cd21b43ecd21cd20b44fcd2173c2ebf62a2e636f6d00 }


condition:
	$a0
}