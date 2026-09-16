rule Win_Trojan_Duwende_11
{
strings:
	$a0 = { ba7600b103cd215a8b441a2bc129d08944015a59585051cd2189f2b103b440cd2159588b541a }


condition:
	$a0
}