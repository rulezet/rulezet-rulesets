rule Win_Trojan_Unicode_61_53_160_46_1
{
strings:
	$a0 = { 360031002e00350033002e003100360030002e00340036 }


condition:
	$a0
}