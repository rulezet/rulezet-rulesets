rule Win_Trojan_S_2
{
strings:
	$a0 = { 061fb43db002cd211fa32b0072b5 }


condition:
	$a0
}