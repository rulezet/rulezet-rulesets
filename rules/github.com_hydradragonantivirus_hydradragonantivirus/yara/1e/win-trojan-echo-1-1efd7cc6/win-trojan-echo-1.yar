rule Win_Trojan_Echo_1
{
strings:
	$a0 = { 0500550000000600ffff18030000e0000000050000001803 }


condition:
	$a0
}