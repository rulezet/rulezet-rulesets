rule Win_Trojan_Gen_89
{
strings:
	$a0 = { ecfcc383c30381fbcc0272e95be8890ae421 }


condition:
	$a0
}