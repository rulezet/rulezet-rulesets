rule Win_Trojan_Peed_260
{
strings:
	$a0 = { 85c287debada74a40d730068a86001005981c18846000081c18846000068ae??2d005e56 }


condition:
	$a0
}