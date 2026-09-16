rule Win_Trojan_AntiPas_3
{
strings:
	$a0 = { 51565753ff360c01eb4c }


condition:
	$a0
}