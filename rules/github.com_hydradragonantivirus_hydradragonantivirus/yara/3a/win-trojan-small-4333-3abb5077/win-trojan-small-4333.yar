rule Win_Trojan_Small_4333
{
strings:
	$a0 = { e8??000000e8??000000e8??0000005052585a[0-255]bb0000c0fff7d3 }


condition:
	$a0
}