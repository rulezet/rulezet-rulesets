rule Win_Trojan_Mithrandir_2
{
strings:
	$a0 = { 9c2e891650012e8c1e52013d004b7503e8d2fe9dea }


condition:
	$a0
}