rule Win_Trojan_Bancos_657
{
strings:
	$a0 = { 449fd909985543c6e61c7cd61a0314e73978ca14f9834478ec6667aa33fe6d2070bc87d341d88f9839a30abdab391acb5e8d37ac19d4993b18002ead6fc8e7f7f9093ca9 }


condition:
	$a0
}