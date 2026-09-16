rule Win_Trojan_Dikshev_36
{
strings:
	$a0 = { 9e00bf400157acaa3c2e75fabe3c01a5a55ab45bb90001cd21720b93b440ba40009087d1cd21 }


condition:
	$a0
}