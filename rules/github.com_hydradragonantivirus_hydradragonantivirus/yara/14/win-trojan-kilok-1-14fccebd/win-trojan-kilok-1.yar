rule Win_Trojan_Kilok_1
{
strings:
	$a0 = { 0200550008000100fffff40f0000bc030000040000001b03 }


condition:
	$a0
}