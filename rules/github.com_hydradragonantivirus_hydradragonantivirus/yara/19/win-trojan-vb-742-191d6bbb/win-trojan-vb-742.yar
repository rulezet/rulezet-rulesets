rule Win_Trojan_VB_742
{
strings:
	$a0 = { 4e6f56696f6c656e6365 }

	$a1 = { 5c002a002e006500780065[0-33]660069006c0065002e006500780065 }


condition:
	$a0 and $a1
}