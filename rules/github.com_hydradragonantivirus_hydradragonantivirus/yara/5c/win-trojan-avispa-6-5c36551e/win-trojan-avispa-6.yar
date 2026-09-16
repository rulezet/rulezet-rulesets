rule Win_Trojan_Avispa_6
{
strings:
	$a0 = { 80e900565e9033c1565e2e8907565e439043565eb80000575f050000575f903bd8575f72d1 }


condition:
	$a0
}