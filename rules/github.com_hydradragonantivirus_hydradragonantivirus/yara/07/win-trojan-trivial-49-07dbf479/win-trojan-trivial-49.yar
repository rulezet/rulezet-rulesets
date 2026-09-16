rule Win_Trojan_Trivial_49
{
strings:
	$a0 = { 4eba4901cd21b8013dba9e00cd218bd8ba00018a264801b96a00cd21b44fcd2173e4b409ba4f01 }


condition:
	$a0
}