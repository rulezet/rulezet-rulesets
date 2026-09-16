rule Win_Trojan_Alma_2
{
strings:
	$a0 = { e8000000005b6805104000582bd8535d8dbd21104000b97991000080370047e2fa }


condition:
	$a0
}