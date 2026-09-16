rule Win_Trojan_VB_1025
{
strings:
	$a0 = { 6838404000e8eeffffff00000000000030 }

	$a1 = { 57696e646f7773323030302044756d6d79204c6f636b }


condition:
	$a0 and $a1
}