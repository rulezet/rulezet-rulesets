rule Win_Trojan_Small_5374
{
strings:
	$a0 = { e8??000000e9??000000[0-255]bb0000c0fff7d3ffc382cb0081e800440000f7d0 }


condition:
	$a0
}