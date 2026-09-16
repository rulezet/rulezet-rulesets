rule Win_Trojan_EraseA_1
{
strings:
	$a0 = { b002b9202099cd26cd20 }


condition:
	$a0
}