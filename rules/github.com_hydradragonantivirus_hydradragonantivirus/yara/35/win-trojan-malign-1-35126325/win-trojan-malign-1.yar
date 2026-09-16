rule Win_Trojan_Malign_1
{
strings:
	$a0 = { 014c3fde9a4d616c69676e243f03004008013e00b801709f0001400f8d1391022a2e636f6d00eb04ca0d8c }


condition:
	$a0
}