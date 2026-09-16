rule Win_Trojan__0242_0001_002_1
{
strings:
	$a0 = { e88c00b002e87d00b4408d966f0359cd21b8024233c999cd21b42ccd210bd274f889960901 }


condition:
	$a0
}