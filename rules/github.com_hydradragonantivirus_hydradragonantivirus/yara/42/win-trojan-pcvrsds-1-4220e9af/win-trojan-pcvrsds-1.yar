rule Win_Trojan_PCVRSDS_1
{
strings:
	$a0 = { 1c00b94f072e8a9708002e001046e2 }


condition:
	$a0
}