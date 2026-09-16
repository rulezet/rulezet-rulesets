rule Win_Trojan_Mex_2
{
strings:
	$a0 = { 558bec5168a41040006a006a00ff1504104000a3a0104000833da0104000007513 }


condition:
	$a0
}