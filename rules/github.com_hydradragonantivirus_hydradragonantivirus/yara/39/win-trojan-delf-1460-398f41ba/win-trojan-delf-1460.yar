rule Win_Trojan_Delf_1460
{
strings:
	$a0 = { e8e7f3ffff8b155cbc4000b8b8974000e807aaffff85c07f09833d5cbc400000750fb85cbc4000baec974000e823a6ffff }


condition:
	$a0
}