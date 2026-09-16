rule Win_Trojan_Small_4334
{
strings:
	$a0 = { e8400000006a0050e864000000e8880000005052585a56 }


condition:
	$a0
}