rule Win_Trojan_VisuaLand_1
{
strings:
	$a0 = { 0500559e0000020003000000000065050000050000000103 }


condition:
	$a0
}