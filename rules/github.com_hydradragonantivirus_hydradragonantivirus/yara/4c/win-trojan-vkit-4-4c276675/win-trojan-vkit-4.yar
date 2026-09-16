rule Win_Trojan_VKit_4
{
strings:
	$a0 = { a7059a32036b059a0d0009055589e5b800019acd02a70581ec00019a2e006b059a71026b059a6b0ea705b00750 }


condition:
	$a0
}