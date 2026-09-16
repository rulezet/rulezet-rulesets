rule Win_Trojan_Small_4399
{
strings:
	$a0 = { 56575355e8??000000e8??000000e8??0000008d2d????3826e8 }


condition:
	$a0
}