rule Win_Trojan_C_5
{
strings:
	$a0 = { f2ab0e07c300000020070f0a0f0a0f0a0f0a0f0a0f0a0f0a0f0af70eee0c90fb505152535556571e060e1feb0b90 }


condition:
	$a0
}