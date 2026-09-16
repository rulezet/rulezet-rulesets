rule Win_Trojan_Gippo_5
{
strings:
	$a0 = { 1e060e1fb95a022fbe3200478b1cba552d0bdaf7d3 }


condition:
	$a0
}