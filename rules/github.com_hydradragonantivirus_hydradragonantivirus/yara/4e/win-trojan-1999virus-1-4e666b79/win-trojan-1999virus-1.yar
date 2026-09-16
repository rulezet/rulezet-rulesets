rule Win_Trojan_1999virus_1
{
strings:
	$a0 = { 0c068c009ac8058c009a0e028c00b001b9ff00ba0000cd26bf52011e57b02e5031c0509a0c06 }


condition:
	$a0
}