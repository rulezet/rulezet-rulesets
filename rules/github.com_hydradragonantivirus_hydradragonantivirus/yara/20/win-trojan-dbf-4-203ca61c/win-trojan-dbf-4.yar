rule Win_Trojan_DBF_4
{
strings:
	$a0 = { c38cc02e03441a051000502eff74 }


condition:
	$a0
}