rule Win_Trojan_VirusC_1
{
strings:
	$a0 = { 5803c72d0400be35012e8904e85cffb440ba3401b90300cd7ce859ffb440ba0001b9f001cd7c }


condition:
	$a0
}