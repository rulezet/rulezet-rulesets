rule Win_Trojan_Small_4412
{
strings:
	$a0 = { 558becb83c250000e8f206000056e86bfeffff33f684c07509e8 }


condition:
	$a0
}