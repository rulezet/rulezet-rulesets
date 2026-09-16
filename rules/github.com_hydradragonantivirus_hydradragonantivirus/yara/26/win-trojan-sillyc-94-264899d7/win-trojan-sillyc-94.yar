rule Win_Trojan_SillyC_94
{
strings:
	$a0 = { ba00fea1c601a3c801b41acd21b42acd2180fa0d74043c0075198d168f01e88900726d8bd7b441cd218d168f01 }


condition:
	$a0
}