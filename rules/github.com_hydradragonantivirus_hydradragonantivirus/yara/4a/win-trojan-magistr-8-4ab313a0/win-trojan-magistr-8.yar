rule Win_Trojan_Magistr_8
{
strings:
	$a0 = { 67ff3600005464678f060000 }


condition:
	$a0
}