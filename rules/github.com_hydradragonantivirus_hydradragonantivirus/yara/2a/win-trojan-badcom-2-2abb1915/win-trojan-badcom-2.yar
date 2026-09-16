rule Win_Trojan_BadCOM_2
{
strings:
	$a0 = { 03f9b92900303d47e2fbfcbf0001be39035903f151 }


condition:
	$a0
}