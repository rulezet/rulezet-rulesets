rule Win_Trojan_Peed_316
{
strings:
	$a0 = { b96e090100baffbbbffff7d289d652ad05 }


condition:
	$a0
}