rule Win_Trojan_Peed_299
{
strings:
	$a0 = { 682a2577005de89e0000005589e5518b7d14b9 }


condition:
	$a0
}