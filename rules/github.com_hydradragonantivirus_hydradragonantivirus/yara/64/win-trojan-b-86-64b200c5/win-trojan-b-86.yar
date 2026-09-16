rule Win_Trojan_B_86
{
strings:
	$a0 = { 33c08ed88ed0bcfefffb1eff0e1304cd12b10ad3c8c41e4c00891eb77d8c06b97dc7064c008d00 }


condition:
	$a0
}