rule Win_Trojan_Hydra_17
{
strings:
	$a0 = { 0600e81300eb3690be4801bf5a01b912008034f5 }


condition:
	$a0
}