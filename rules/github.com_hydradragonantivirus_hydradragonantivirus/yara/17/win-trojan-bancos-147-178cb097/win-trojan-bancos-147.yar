rule Win_Trojan_Bancos_147
{
strings:
	$a0 = { 1b115e41d2a73cd5a1fcad1a1de855cab0774bee8c81b220d7292b0ec7af0c2aead9bed607a21330700b8ba891d908ebedd6ce55aeeba6c0d6bf4971e1d6a156 }


condition:
	$a0
}