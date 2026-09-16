rule Win_Trojan_Codewar_4
{
strings:
	$a0 = { be007cfa8be68ed7fb8ec7b80402bb007eb90400ba }


condition:
	$a0
}