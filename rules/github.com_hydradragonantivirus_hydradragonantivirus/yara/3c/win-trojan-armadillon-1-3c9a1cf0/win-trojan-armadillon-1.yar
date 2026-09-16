rule Win_Trojan_Armadillon_1
{
strings:
	$a0 = { 01040055c000000000ffff540300000f020000030000005403 }


condition:
	$a0
}