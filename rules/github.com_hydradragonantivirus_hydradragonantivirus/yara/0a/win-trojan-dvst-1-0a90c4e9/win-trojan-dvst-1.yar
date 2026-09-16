rule Win_Trojan_Dvst_1
{
strings:
	$a0 = { 0239060000741db8010341cdcdbebe03bfbe01b121f3a5c606770180b801034133dbcdcdc606 }


condition:
	$a0
}