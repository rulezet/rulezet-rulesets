rule Win_Trojan_Wharps_1
{
strings:
	$a0 = { e800005d81ed0601e80200eb1233ff8db622018bfeb99d01ac34 }


condition:
	$a0
}