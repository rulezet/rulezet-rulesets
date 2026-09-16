rule Win_Trojan_Peed_230
{
strings:
	$a0 = { ba65b8400087d16a006a006a006a006a006a0054ff1183ec }


condition:
	$a0
}