rule Win_Trojan_Bancos_1810
{
strings:
	$a0 = { d5ac024dadaa713a8a8ee708e5e53057fefcacf74f2ac38c85c177b515473beca374f072ad9a6299b6b15bfe0e82b2f305857d8a4b725f24ac0c565c3a20e6e45e104605966f }


condition:
	$a0
}