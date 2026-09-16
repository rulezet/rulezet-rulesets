rule Win_Trojan_VB_1713
{
strings:
	$a0 = { 6b657565706b000700000060a240000700000014 }


condition:
	$a0
}