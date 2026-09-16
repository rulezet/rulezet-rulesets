rule Win_Trojan_Kitana_14
{
strings:
	$a0 = { 8ac88bd8cd13803f85740ec740fd55aa418d00cd1387f3e2f8c387f3970e1fff0e1304cd12 }


condition:
	$a0
}