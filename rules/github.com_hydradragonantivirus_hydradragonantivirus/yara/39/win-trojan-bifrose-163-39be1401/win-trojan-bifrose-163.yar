rule Win_Trojan_Bifrose_163
{
strings:
	$a0 = { 19b704814a88ce5fc79430d1d69e100025f6b1ff03e7f58b0508d7e18864c0f0a7bffa0055fedbcb047acaaf00a878b201c28a5d02981e01d1055281cae67ae853c1016c }


condition:
	$a0
}