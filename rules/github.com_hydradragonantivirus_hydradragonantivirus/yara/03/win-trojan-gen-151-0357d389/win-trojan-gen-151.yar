rule Win_Trojan_Gen_151
{
strings:
	$a0 = { 652f534d465d8dbe00ff165731c0509acc064f00bf50001e57bf94001e57bf9e001e579a7c }


condition:
	$a0
}