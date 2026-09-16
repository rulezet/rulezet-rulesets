rule Win_Trojan_Small_4332
{
strings:
	$a0 = { e8??000000e8??000000[0-255]c744f6ffffffe755582d58484705c3bb999bed }


condition:
	$a0
}