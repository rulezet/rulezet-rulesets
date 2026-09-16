rule Win_Trojan_Daffy_1
{
strings:
	$a0 = { 4896c6534b15d68b3fffbf1687073aaf3f168d16f205119639f83ee9d6913fa23aaf3f52f2001196 }


condition:
	$a0
}