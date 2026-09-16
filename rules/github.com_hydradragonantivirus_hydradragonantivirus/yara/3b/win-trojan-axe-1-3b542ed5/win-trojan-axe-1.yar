rule Win_Trojan_Axe_1
{
strings:
	$a0 = { aa17999c998767741e15a44a1028aaec8a55677484f43d5599871345aaa24bde60de7aedaa176774 }


condition:
	$a0
}