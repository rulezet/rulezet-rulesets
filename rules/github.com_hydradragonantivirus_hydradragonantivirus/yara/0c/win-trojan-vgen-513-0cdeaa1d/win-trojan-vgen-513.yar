rule Win_Trojan_VGEN_513
{
strings:
	$a0 = { c9e88c00b002e87d00b4408d965c0359cd21b8024233c999cd21b42ccd210bd274f889960b01 }


condition:
	$a0
}