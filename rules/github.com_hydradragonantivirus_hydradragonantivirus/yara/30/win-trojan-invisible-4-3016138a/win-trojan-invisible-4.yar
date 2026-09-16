rule Win_Trojan_Invisible_4
{
strings:
	$a0 = { bace3c7700f5f587c081c1625575007f009c9d30972b9e87c94300f2e2f5 }


condition:
	$a0
}