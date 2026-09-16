rule Win_Trojan_USSR_16
{
strings:
	$a0 = { 1e010183c303b104d3eb8cd803c3 }


condition:
	$a0
}