rule Win_Trojan_VGEN_20
{
strings:
	$a0 = { bf19015061c35751508b }


condition:
	$a0
}