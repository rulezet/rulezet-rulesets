rule Win_Trojan_Lazar_2
{
strings:
	$a0 = { 04cd1a81fa17127223b9010033d2bb8b00be357cb40242cd10b409ac34f0cd103c2175f0e670e6 }


condition:
	$a0
}