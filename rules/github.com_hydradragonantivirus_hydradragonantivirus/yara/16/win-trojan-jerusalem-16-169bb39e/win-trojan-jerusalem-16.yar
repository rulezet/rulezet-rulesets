rule Win_Trojan_Jerusalem_16
{
strings:
	$a0 = { e0cd2180ec037511368b0e5202bf0001b4ddbee60303f7cd218cc82df0ff8ed0bc400450b84300 }


condition:
	$a0
}