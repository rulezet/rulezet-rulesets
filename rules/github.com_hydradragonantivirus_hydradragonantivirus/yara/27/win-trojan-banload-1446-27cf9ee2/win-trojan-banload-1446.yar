rule Win_Trojan_Banload_1446
{
strings:
	$a0 = { 756e74[18]31323334353637[1]3839414243444546[7]4e53622655 }


condition:
	$a0
}