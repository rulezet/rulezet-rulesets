rule Win_Trojan_Trojan_651
{
strings:
	$a0 = { 706c656173652072652d656e7465722079 }

	$a1 = { 2f726f6d2e706c[0-30]6175746f636f6d706c6574653d226f666622 }


condition:
	$a0 and $a1
}