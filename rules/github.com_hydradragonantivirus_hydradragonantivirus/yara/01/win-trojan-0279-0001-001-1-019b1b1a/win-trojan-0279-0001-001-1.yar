rule Win_Trojan__0279_0001_001_1
{
strings:
	$a0 = { e8bdffb002e878ffb4408d96ab0259cd21b8024233c999cd21b42ccd210bd274f8898e0b01 }


condition:
	$a0
}