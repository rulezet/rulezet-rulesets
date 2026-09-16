rule Win_Trojan_CCCP_1
{
strings:
	$a0 = { 010181ee00028d3ef80403fe2eff052e8b053d19007520b4098d16760303d6cd212ec7050000b9900151b40c86 }


condition:
	$a0
}