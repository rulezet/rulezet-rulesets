rule Win_Trojan_Peed_85
{
strings:
	$a0 = { 68bdcaffffe9??000000 }


condition:
	$a0
}