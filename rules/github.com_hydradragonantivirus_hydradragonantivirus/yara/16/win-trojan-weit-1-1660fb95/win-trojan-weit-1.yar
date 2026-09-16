rule Win_Trojan_Weit_1
{
strings:
	$a0 = { ad00000020004a0028000a016700ffff6700ffff2000c000bf000000ae0420004a002800540040006b }


condition:
	$a0
}