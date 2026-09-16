rule Win_Trojan_XXX_1
{
strings:
	$a0 = { 905605b8eeffcd213dffee744e2ec606dc04ff90b42acd2180fa13 }


condition:
	$a0
}