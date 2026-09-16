rule Win_Trojan_CivilWar_13
{
strings:
	$a0 = { fca07505b801009dcf1e0657565053515280fc40750583 }


condition:
	$a0
}