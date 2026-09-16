rule Win_Trojan_Apocalipse_1
{
strings:
	$a0 = { 5ed0c0b93b03fec02e81341192fec446fec246d0c0e2f1 }


condition:
	$a0
}