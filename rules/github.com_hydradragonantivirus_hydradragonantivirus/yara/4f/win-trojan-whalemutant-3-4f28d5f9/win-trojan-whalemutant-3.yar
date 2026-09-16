rule Win_Trojan_WhaleMutant_3
{
strings:
	$a0 = { c361dce81f00b8020081379a239001c3e2f781c38d00 }


condition:
	$a0
}