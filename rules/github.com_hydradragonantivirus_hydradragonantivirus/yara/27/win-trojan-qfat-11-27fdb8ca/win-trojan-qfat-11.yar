rule Win_Trojan_QFat_11
{
strings:
	$a0 = { 07b9ff00ba0000cd26b006b9ff00ba0000cd26b005b9ff00ba0000cd26b004b9ff00ba0000cd26 }


condition:
	$a0
}