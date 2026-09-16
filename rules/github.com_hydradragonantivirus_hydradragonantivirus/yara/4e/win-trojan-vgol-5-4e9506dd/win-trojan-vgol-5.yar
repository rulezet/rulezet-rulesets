rule Win_Trojan_VGOL_5
{
strings:
	$a0 = { b93c07e8f0fc3d3c077528803e3c074d740abad601b4 }


condition:
	$a0
}