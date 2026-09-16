rule Win_Trojan_Hi_3
{
strings:
	$a0 = { 1304c7066401d32e4ab10689161304d3e2b940008cc0 }


condition:
	$a0
}