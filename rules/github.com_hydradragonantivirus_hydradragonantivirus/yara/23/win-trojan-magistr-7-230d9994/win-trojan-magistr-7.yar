rule Win_Trojan_Magistr_7
{
strings:
	$a0 = { 6467ff3600005464678f060000 }


condition:
	$a0
}