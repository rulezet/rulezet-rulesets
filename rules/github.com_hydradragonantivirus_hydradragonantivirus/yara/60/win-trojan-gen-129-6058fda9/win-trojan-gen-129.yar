rule Win_Trojan_Gen_129
{
strings:
	$a0 = { 49b742473a2575153a7d0175103a4502750bc64502 }


condition:
	$a0
}