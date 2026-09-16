rule Win_Trojan_POSCardStealer_1
{
strings:
	$a0 = { 68dd12470068d2124700 }


condition:
	$a0
}