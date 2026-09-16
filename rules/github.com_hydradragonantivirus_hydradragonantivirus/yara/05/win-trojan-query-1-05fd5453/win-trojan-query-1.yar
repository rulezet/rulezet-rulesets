rule Win_Trojan_Query_1
{
strings:
	$a0 = { 0200558e00000100ffff18030000c7020000050000001803 }


condition:
	$a0
}