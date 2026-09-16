rule Win_Trojan_Peed_296
{
strings:
	$a0 = { 8d9032f6000057e86300000051b9f401000089d7 }


condition:
	$a0
}