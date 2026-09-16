rule Win_Trojan_Delf_2260
{
strings:
	$a0 = { 558bec83c4c4b84c424000e824f3ffffe843ebffff8d40 }

	$a1 = { 667762646c6c2e646c6c0054657374 }


condition:
	$a0 and $a1
}