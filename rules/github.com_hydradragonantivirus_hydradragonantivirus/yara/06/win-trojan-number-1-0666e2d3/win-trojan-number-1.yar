rule Win_Trojan_Number_1
{
strings:
	$a0 = { 626572204f6e6521e88bf7bf9f2d0ee8 }


condition:
	$a0
}