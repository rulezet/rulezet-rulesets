rule Win_Trojan_CivilWar_15
{
strings:
	$a0 = { fca07505b801009dcf1e065756505351523d004b750d2e }


condition:
	$a0
}