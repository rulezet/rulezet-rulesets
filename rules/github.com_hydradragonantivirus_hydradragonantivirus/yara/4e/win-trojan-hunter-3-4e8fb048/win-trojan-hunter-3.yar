rule Win_Trojan_Hunter_3
{
strings:
	$a0 = { 01030055df010006000200090300009c000000030000000903 }


condition:
	$a0
}