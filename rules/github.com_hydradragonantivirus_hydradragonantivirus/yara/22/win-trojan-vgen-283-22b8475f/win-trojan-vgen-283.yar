rule Win_Trojan_VGEN_283
{
strings:
	$a0 = { 81ed03018b0ecb01890ead01b41aba00fecd21b44e33c9bacd01cd217310eb7390b43ecd21b44fbacd01cd217265b8 }


condition:
	$a0
}