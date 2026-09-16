rule Win_Trojan_Virus_5
{
strings:
	$a0 = { 558b2e010181c5030133c033dbb90900 }


condition:
	$a0
}