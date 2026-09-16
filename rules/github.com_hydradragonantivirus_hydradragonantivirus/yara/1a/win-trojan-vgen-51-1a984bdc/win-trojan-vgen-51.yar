rule Win_Trojan_VGEN_51
{
strings:
	$a0 = { 9090b801faba4559cd16e800005d81ed0f018d9e2102ff374343ff37b41a8d962502cd21ccb44e8d961902cd2172 }


condition:
	$a0
}