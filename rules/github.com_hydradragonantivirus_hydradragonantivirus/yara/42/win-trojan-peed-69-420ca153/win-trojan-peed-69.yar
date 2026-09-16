rule Win_Trojan_Peed_69
{
strings:
	$a0 = { 558becb828250000e86506000053 }


condition:
	$a0
}