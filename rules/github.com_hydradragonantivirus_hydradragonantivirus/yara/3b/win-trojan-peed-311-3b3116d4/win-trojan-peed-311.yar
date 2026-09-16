rule Win_Trojan_Peed_311
{
strings:
	$a0 = { ba434343004085c07524ab50525183c8 }


condition:
	$a0
}