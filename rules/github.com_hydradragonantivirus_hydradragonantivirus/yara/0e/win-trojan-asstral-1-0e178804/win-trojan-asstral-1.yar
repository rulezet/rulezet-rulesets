rule Win_Trojan_Asstral_1
{
strings:
	$a0 = { e201ba70012e8134283146464a75f6 }


condition:
	$a0
}