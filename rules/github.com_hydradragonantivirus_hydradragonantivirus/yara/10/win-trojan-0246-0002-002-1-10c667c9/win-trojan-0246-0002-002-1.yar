rule Win_Trojan__0246_0002_002_1
{
strings:
	$a0 = { c9e88c00b002e87d00b4408d96330459cd21b8024233c999cd21b42ccd210bd274f889960b01 }


condition:
	$a0
}