rule Win_Trojan_Pramro_1
{
strings:
	$a0 = { 716977757965697532393833 }


condition:
	$a0
}